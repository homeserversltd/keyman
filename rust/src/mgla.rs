//! Native MGLA v1. Secret material stays inside the existing Keyman crypto
//! membrane; only encrypted credentials and public protocol lines leave it.
use super::{KeymanError, Paths, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::time::Instant;
use zeroize::Zeroizing;

const MAX_BODY: usize = 16 * 1024;
const MAX_BODIES: usize = 64;
const MAX_BATCH: usize = MAX_BODIES * (MAX_BODY + 1);
const MAX_VERIFY_LINE: usize = 64 * 1024;
const FIELDS: [&str; 7] = [
    "product", "band", "licensee", "grant", "issued", "expiry", "key",
];
const USAGE: &str = "Usage: keyman mgla keygen SERVICE | keyline SERVICE | sign SERVICE (1..64 LF-separated bodies on stdin) | verify (key line then attestations on stdin) | succeed OLD NEW";

// The file itself is the lock seat: no extra file or exchange directory.
fn lock(paths: &Paths) -> Result<File> {
    let path = paths.check_fixed_parent("root/key/skeleton.key")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| KeymanError::Io("keyman-lock-failed"))?;
    if !file
        .metadata()
        .map_err(|_| KeymanError::Io("keyman-lock-failed"))?
        .is_file()
        || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0
    {
        return Err(KeymanError::Io("keyman-lock-failed"));
    }
    Ok(file)
}

fn identifier(public: &[u8; 32]) -> String {
    let digest = Sha256::digest(public);
    let mut result = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

fn keyline(key: &VerifyingKey) -> String {
    let public = key.to_bytes();
    format!(
        "MGLA-KEY1|key={}|pub={}",
        identifier(&public),
        URL_SAFE_NO_PAD.encode(public)
    )
}

fn signing_key(paths: &Paths, service: &str) -> Result<SigningKey> {
    let plaintext = super::decrypt_service_key(paths, service)?;
    // Exactly the Python-minted record, not a second credential format.
    let hex = plaintext
        .strip_prefix(b"username=\"mgla\"\npassword=\"")
        .and_then(|value| value.strip_suffix(b"\"\n"))
        .filter(|value| value.len() == 64)
        .ok_or(KeymanError::Input("invalid-keyman-credential"))?;
    let mut seed = Zeroizing::new([0u8; 32]);
    for (slot, pair) in seed.iter_mut().zip(hex.chunks_exact(2)) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(KeymanError::Input("invalid-keyman-credential")),
        };
        *slot = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    // ed25519-dalek's explicitly enabled zeroize feature wipes SigningKey
    // on drop; seed and decrypted record are separately RAII-zeroized.
    Ok(SigningKey::from_bytes(&seed))
}

fn emit(output: &[u8]) -> Result<()> {
    io::stdout()
        .lock()
        .write_all(output)
        .map_err(|_| KeymanError::Io("cannot-write-mgla-output"))
}

fn keygen(paths: &Paths, service: &str, kid: &mut String) -> Result<()> {
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err(KeymanError::Input("keygen-requires-tty"));
    }
    if [
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "WOODPECKER",
        "BUILDKITE",
        "JENKINS_URL",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
    {
        return Err(KeymanError::Input("keygen-forbidden-in-ci"));
    }
    let _lock = lock(paths)?;
    let target = paths.checked_key_path(service)?;
    match fs::symlink_metadata(&target) {
        Ok(_) => return Err(KeymanError::Input("credential-exists-overwrite-refused")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(KeymanError::Io("credential-state-unreadable")),
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(|_| KeymanError::Crypto)?;
    let key = SigningKey::from_bytes(&seed);
    *kid = identifier(&key.verifying_key().to_bytes());
    let mut hex = Zeroizing::new(Vec::with_capacity(64));
    for byte in seed.iter() {
        hex.push(super::PASSWORD_ALPHABET[(byte >> 4) as usize]);
        hex.push(super::PASSWORD_ALPHABET[(byte & 15) as usize]);
    }
    let content = super::format_credentials(b"mgla", &hex)?;
    let skeleton = paths.read_skeleton()?;
    let suite = super::suite_password(paths, &skeleton)?;
    let encrypted = super::encrypt_blob(&suite, &content)?;
    // Recheck atomically at creation: a preflight alone cannot prevent races.
    super::write_new_exclusive(&target, &encrypted, "credential-exists-overwrite-refused")?;
    emit(format!("key={kid}\n{}\n", keyline(&key.verifying_key())).as_bytes())
}

fn body_key(body: &[u8]) -> Result<&str> {
    if body.starts_with(b"MGLA-KEY1|") {
        return Err(KeymanError::Input("key-line-is-not-an-attestation"));
    }
    if body.len() > MAX_BODY || !body.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return Err(KeymanError::Input("invalid-mgla1-body"));
    }
    let text = std::str::from_utf8(body).map_err(|_| KeymanError::Input("invalid-mgla1-body"))?;
    let mut pieces = text.split('|');
    if pieces.next() != Some("MGLA1") {
        return Err(KeymanError::Input("invalid-mgla1-body"));
    }
    let mut kid = "";
    for field in FIELDS {
        let (name, value) = pieces
            .next()
            .and_then(|piece| piece.split_once('='))
            .ok_or(KeymanError::Input("invalid-mgla1-body"))?;
        if name != field || value.is_empty() {
            return Err(KeymanError::Input("invalid-mgla1-body"));
        }
        kid = value;
    }
    if pieces.next().is_some() {
        return Err(KeymanError::Input("invalid-mgla1-body"));
    }
    Ok(kid)
}

fn sign(paths: &Paths, service: &str, kid: &mut String, count: &mut usize) -> Result<()> {
    let mut input = Vec::with_capacity(MAX_BATCH + 1);
    io::stdin()
        .lock()
        .take(MAX_BATCH as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| KeymanError::Io("cannot-read-mgla-input"))?;
    if input.len() > MAX_BATCH {
        return Err(KeymanError::Input("mgla-batch-too-large"));
    }
    let input = input.strip_suffix(b"\n").unwrap_or(&input);
    let bodies: Vec<_> = input
        .split(|byte| *byte == b'\n')
        .take(MAX_BODIES + 1)
        .collect();
    *count = bodies.len();
    if input.is_empty() || bodies.len() > MAX_BODIES {
        return Err(KeymanError::Input("mgla-batch-requires-1-to-64-bodies"));
    }
    for body in &bodies {
        body_key(body)?;
    }
    let _lock = lock(paths)?;
    let key = signing_key(paths, service)?; // One credential decryption per batch.
    *kid = identifier(&key.verifying_key().to_bytes());
    for body in &bodies {
        if body_key(body)? != kid {
            return Err(KeymanError::Input("key-id-mismatch"));
        }
    }
    // No signature or stdout bytes exist until the whole batch is validated.
    let mut output = Vec::with_capacity(input.len() + bodies.len() * 92);
    for body in bodies {
        let signature = key.sign(body);
        output.extend_from_slice(body);
        output.extend_from_slice(b"|sig=");
        output.extend_from_slice(URL_SAFE_NO_PAD.encode(signature.to_bytes()).as_bytes());
        output.push(b'\n');
    }
    drop(key);
    emit(&output)
}

fn succeed(paths: &Paths, old: &str, new: &str, kid: &mut String) -> Result<()> {
    if old == new {
        return Err(KeymanError::Input("succession-services-must-differ"));
    }
    let _lock = lock(paths)?;
    let old_key = signing_key(paths, old)?;
    let new_key = signing_key(paths, new)?;
    *kid = identifier(&old_key.verifying_key().to_bytes());
    let new_public = new_key.verifying_key().to_bytes();
    let new_id = identifier(&new_public);
    drop(new_key);
    if *kid == new_id {
        return Err(KeymanError::Input("succession-keys-must-differ"));
    }
    let body = format!(
        "MGLA-SUCC1|old={kid}|new={new_id}|pub={}",
        URL_SAFE_NO_PAD.encode(new_public)
    );
    let signature = old_key.sign(body.as_bytes());
    drop(old_key);
    emit(
        format!(
            "{body}|ssig={}\n",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
        .as_bytes(),
    )
}

// Keep only one bounded public record, discarding overflow through its LF so
// the next record is still judged. Reads create no file, receipt, or log.
fn record(reader: &mut impl BufRead, limit: usize) -> Result<Option<(Vec<u8>, bool)>> {
    let mut bytes = Vec::new();
    let mut overflow = false;
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| KeymanError::Io("cannot-read-mgla-input"))?;
        if available.is_empty() {
            return Ok(if bytes.is_empty() && !overflow {
                None
            } else {
                Some((bytes, overflow))
            });
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let end = newline.unwrap_or(available.len());
        let take = end.min(limit - bytes.len());
        bytes.extend_from_slice(&available[..take]);
        overflow |= take < end;
        reader.consume(end + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some((bytes, overflow)));
        }
    }
}

fn strip_padding(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == 0)
    {
        bytes = &bytes[1..];
    }
    while bytes
        .last()
        .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == 0)
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn parse_keyline(line: &[u8]) -> Result<VerifyingKey> {
    let line = std::str::from_utf8(strip_padding(line))
        .map_err(|_| KeymanError::Input("invalid-mgla-key-line"))?;
    let (kid, public) = line
        .strip_prefix("MGLA-KEY1|key=")
        .and_then(|line| line.split_once("|pub="))
        .ok_or(KeymanError::Input("invalid-mgla-key-line"))?;
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(KeymanError::Input("invalid-mgla-key-line"))?;
    if kid != identifier(&public) {
        return Err(KeymanError::Input("key-id-mismatch"));
    }
    VerifyingKey::from_bytes(&public).map_err(|_| KeymanError::Input("invalid-mgla-public-key"))
}

fn verify_line(line: &[u8], public: &VerifyingKey) -> &'static str {
    let bytes = strip_padding(line);
    if !bytes.starts_with(b"MGLA1|") {
        return if bytes.starts_with(b"MGLA") {
            "UNKNOWN format version beyond this verifier"
        } else {
            "INVALID not an MGLA line"
        };
    }
    let Ok(line) = std::str::from_utf8(bytes) else {
        return "INVALID malformed UTF-8";
    };
    let Some((body, signature)) = line.rsplit_once("|sig=") else {
        return "INVALID missing signature field";
    };
    let mut pieces = body.split('|').skip(1);
    let mut kid = "";
    for field in FIELDS {
        let Some((name, value)) = pieces.next().and_then(|piece| piece.split_once('=')) else {
            return "INVALID field set or order is not MGLA1";
        };
        if name != field || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
            return "INVALID field set or order is not MGLA1";
        }
        kid = value;
    }
    if pieces.next().is_some() {
        return "INVALID field set or order is not MGLA1";
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok());
    let Some(signature) = signature else {
        return "INVALID malformed signature";
    };
    if public.verify_strict(body.as_bytes(), &signature).is_err() {
        return "INVALID signature does not verify";
    }
    if kid != identifier(&public.to_bytes()) {
        return "INVALID key id does not match the supplied public key";
    }
    "VALID"
}

fn verify() -> Result<()> {
    let mut reader = io::stdin().lock();
    let (line, overflow) =
        record(&mut reader, 256)?.ok_or(KeymanError::Input("missing-mgla-key-line"))?;
    if overflow {
        return Err(KeymanError::Input("invalid-mgla-key-line"));
    }
    let public = parse_keyline(&line)?;
    let mut count = 0;
    let mut all_valid = true;
    while let Some((line, overflow)) = record(&mut reader, MAX_VERIFY_LINE)? {
        let verdict = if overflow {
            "INVALID input exceeds the supported size limit"
        } else {
            verify_line(&line, &public)
        };
        all_valid &= verdict == "VALID";
        emit(format!("{verdict}\n").as_bytes())?;
        count += 1;
    }
    if count == 0 {
        return Err(KeymanError::Input("missing-mgla-attestation"));
    }
    if all_valid {
        Ok(())
    } else {
        Err(KeymanError::Reported(1))
    }
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let action = args.first().map(String::as_str).unwrap_or("");
    if action == "verify" && args.len() == 1 {
        return verify();
    }
    if matches!(action, "help" | "--help" | "-h") {
        return emit(format!("{USAGE}\n").as_bytes());
    }
    let deed = matches!(action, "keygen" | "sign" | "succeed");
    let start = Instant::now();
    let mut kid = String::from("-");
    let mut count = usize::from(action == "keygen" || action == "succeed");
    let service = args.get(1).map(String::as_str).unwrap_or("-");
    let result = (|| {
        if !((matches!(action, "keygen" | "keyline" | "sign") && args.len() == 2)
            || (action == "succeed" && args.len() == 3))
        {
            return Err(KeymanError::Usage(USAGE));
        }
        super::validate_service(service, true)?;
        if action == "succeed" {
            super::validate_service(&args[2], true)?;
        }
        let paths = Paths::from_environment()?;
        match action {
            "keygen" => keygen(&paths, service, &mut kid),
            "sign" => sign(&paths, service, &mut kid, &mut count),
            "succeed" => succeed(&paths, service, &args[2], &mut kid),
            "keyline" => {
                let _lock = lock(&paths)?;
                let key = signing_key(&paths, service)?;
                let line = keyline(&key.verifying_key());
                drop(key);
                emit(format!("{line}\n").as_bytes())
            }
            _ => Err(KeymanError::Usage(USAGE)),
        }
    })();
    if deed {
        let safe_service = if super::validate_service(service, true).is_ok() {
            service
        } else {
            "-"
        };
        // One Canonical Log Line, metadata only; no persistent sidecar/ledger.
        let line = serde_json::json!({"who":"keyman", "uid":unsafe {libc::geteuid()},
            "verb":action, "service":safe_service, "key":kid, "count":count,
            "outcome":if result.is_ok() {"ok"} else {"refused"},
            "duration_ms":start.elapsed().as_millis(),
            "signal":result.as_ref().err().map(|error| error.message())});
        let mut encoded = line.to_string();
        encoded.push('\n');
        // A failed deed sink is an I/O failure, even if public output or a
        // mint already happened. Do not claim success or retry a broken sink.
        io::stderr()
            .lock()
            .write_all(encoded.as_bytes())
            .map_err(|_| KeymanError::Reported(2))?;
        // The deed already carries the named refusal; do not log it twice.
        result.map_err(|error| KeymanError::Reported(error.exit_code()))
    } else {
        result
    }
}
