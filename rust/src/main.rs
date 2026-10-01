use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use serde_json::{Map, Value};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;

const PBKDF2_ROUNDS: u32 = 10_000;
const SALT_LEN: usize = 8;
const AES_BLOCK_LEN: usize = 16;
const MAX_CRYPTO_INPUT: u64 = 64 * 1024;
const MAX_ENCRYPTED_FILE: u64 = 1024 * 1024;
const MAX_SERVICE_NAME: usize = 238;
const MAX_EXPLICIT_OUTPUT_PATH: usize = 256;
const MAX_FIELD_VALUE: usize = 511;
const MAX_C_LINE: usize = 1023;
const MAX_CREDENTIAL_PLAINTEXT: usize = 1023;
const CLEANUP_DELAY_SECONDS: u64 = 15;
const PASSWORD_ALPHABET: &[u8] = b"0123456789abcdef";

#[derive(Debug)]
enum KeymanError {
    Usage(&'static str),
    Input(&'static str),
    Io(&'static str),
    Crypto,
}

impl KeymanError {
    fn exit_code(&self) -> i32 {
        match self {
            Self::Crypto => 1,
            Self::Io(_) => 2,
            Self::Input(_) => 3,
            Self::Usage(_) => 4,
        }
    }

    fn message(&self) -> &'static str {
        match self {
            Self::Usage(message) | Self::Input(message) | Self::Io(message) => message,
            Self::Crypto => "cryptographic operation failed",
        }
    }
}

type Result<T> = std::result::Result<T, KeymanError>;

struct Paths {
    root: PathBuf,
    rooted: bool,
}

impl Paths {
    fn from_environment() -> Result<Self> {
        let raw = env::var_os("KEYMAN_ROOT");
        let rooted = raw.is_some();
        let raw = raw.unwrap_or_else(|| OsString::from("/"));
        let requested = PathBuf::from(raw);
        if !requested.is_absolute()
            || requested.components().any(|part| {
                matches!(
                    part,
                    Component::ParentDir | Component::CurDir | Component::Prefix(_)
                )
            })
        {
            return Err(KeymanError::Input(
                "KEYMAN_ROOT must be an absolute safe path",
            ));
        }
        let root = fs::canonicalize(&requested)
            .map_err(|_| KeymanError::Io("cannot resolve KEYMAN_ROOT"))?;
        if !root.is_dir() {
            return Err(KeymanError::Io("KEYMAN_ROOT is not a directory"));
        }
        Ok(Self { root, rooted })
    }

    fn fixed(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn argument_path(&self, argument: &str) -> Result<PathBuf> {
        let path = Path::new(argument);
        if !self.rooted {
            return Ok(path.to_path_buf());
        }

        let mut relative = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => relative.push(name),
                _ => return Err(KeymanError::Input("unsafe explicit path")),
            }
        }
        if relative.as_os_str().is_empty() {
            return Err(KeymanError::Input("unsafe explicit path"));
        }

        let mut current = self.root.clone();
        let components: Vec<_> = relative.components().collect();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            let Component::Normal(name) = component else {
                return Err(KeymanError::Input("unsafe explicit path"));
            };
            current.push(name);
            let metadata = fs::symlink_metadata(&current)
                .map_err(|_| KeymanError::Io("cannot inspect explicit path parent"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(KeymanError::Input(
                    "explicit path parent is not a safe directory",
                ));
            }
        }

        let resolved = self.root.join(relative);
        match fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(KeymanError::Input("explicit path must not be a symlink"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(KeymanError::Io("cannot inspect explicit path")),
        }
        Ok(resolved)
    }

    fn skeleton(&self) -> PathBuf {
        self.fixed("root/key/skeleton.key")
    }

    fn vault(&self) -> PathBuf {
        self.fixed("vault/.keys")
    }

    fn suite_key(&self) -> PathBuf {
        self.vault().join("service_suite.key")
    }

    fn exchange(&self) -> PathBuf {
        self.fixed("mnt/keyexchange")
    }

    fn ensure_directories(&self, relative: &str) -> Result<PathBuf> {
        let rel = Path::new(relative);
        if rel.is_absolute()
            || rel
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(KeymanError::Input("unsafe fixed path"));
        }
        let mut current = self.root.clone();
        for component in rel.components() {
            let Component::Normal(name) = component else {
                return Err(KeymanError::Input("unsafe fixed path"));
            };
            current.push(name);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(KeymanError::Io("fixed path contains a non-directory"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current)
                        .map_err(|_| KeymanError::Io("cannot create key directory"))?;
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                        .map_err(|_| KeymanError::Io("cannot secure key directory"))?;
                }
                Err(_) => return Err(KeymanError::Io("cannot inspect key directory")),
            }
        }
        Ok(current)
    }

    fn ensure_key_directories(&self) -> Result<()> {
        self.ensure_directories("root/key")?;
        self.ensure_directories("vault/.keys")?;
        Ok(())
    }

    fn ensure_exchange_directory(&self) -> Result<PathBuf> {
        self.ensure_directories("mnt/keyexchange")
    }

    fn exchange_directory(&self) -> Result<PathBuf> {
        if self.rooted {
            return self.ensure_exchange_directory();
        }
        if !exchange_tmpfs_is_mounted() {
            return Err(KeymanError::Io(
                "required key-exchange tmpfs is not mounted",
            ));
        }
        let path = self.exchange();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| KeymanError::Io("cannot inspect key-exchange directory"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(KeymanError::Io("key-exchange path is not a directory"));
        }
        Ok(path)
    }

    fn check_fixed_parent(&self, relative: &str) -> Result<PathBuf> {
        let rel = Path::new(relative);
        if rel.is_absolute()
            || rel
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(KeymanError::Input("unsafe fixed path"));
        }
        let mut components: Vec<_> = rel.components().collect();
        if components.is_empty() {
            return Err(KeymanError::Input("unsafe fixed path"));
        }
        components.pop();
        let mut current = self.root.clone();
        for component in components {
            let Component::Normal(name) = component else {
                return Err(KeymanError::Input("unsafe fixed path"));
            };
            current.push(name);
            let metadata = fs::symlink_metadata(&current)
                .map_err(|_| KeymanError::Io("cannot inspect key directory"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(KeymanError::Io("fixed path contains a non-directory"));
            }
        }
        Ok(self.root.join(rel))
    }

    fn checked_key_path(&self, service: &str) -> Result<PathBuf> {
        validate_service(service, false)?;
        let relative = format!("vault/.keys/{service}.key");
        self.check_fixed_parent(&relative)
    }

    fn read_skeleton(&self) -> Result<Zeroizing<Vec<u8>>> {
        let relative = "root/key/skeleton.key";
        let path = self.check_fixed_parent(relative)?;
        let bytes = Zeroizing::new(read_regular_file(
            &path,
            MAX_ENCRYPTED_FILE,
            "cannot read skeleton key",
        )?);
        let end = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(bytes.len());
        if end > MAX_FIELD_VALUE || bytes[..end].contains(&0) {
            return Err(KeymanError::Crypto);
        }
        Ok(Zeroizing::new(bytes[..end].to_vec()))
    }

    fn read_key(&self, service: &str) -> Result<Vec<u8>> {
        let path = self.checked_key_path(service)?;
        read_regular_file(&path, MAX_ENCRYPTED_FILE, "cannot read encrypted key")
    }

    fn write_key(&self, service: &str, bytes: &[u8]) -> Result<()> {
        let path = self.checked_key_path(service)?;
        write_atomic(&path, bytes)
    }
}

fn io_error(message: &'static str) -> KeymanError {
    KeymanError::Io(message)
}

fn exchange_tmpfs_is_mounted() -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mounts.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(separator) = fields.iter().position(|field| *field == "-") else {
            return false;
        };
        fields.get(4) == Some(&"/mnt/keyexchange") && fields.get(separator + 1) == Some(&"tmpfs")
    })
}

fn read_regular_file(path: &Path, limit: u64, message: &'static str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| io_error(message))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io_error(message));
    }
    if metadata.len() > limit {
        return Err(KeymanError::Input("input exceeds the supported size limit"));
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| io_error(message))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| io_error(message))?;
    if bytes.len() as u64 > limit {
        return Err(KeymanError::Input("input exceeds the supported size limit"));
    }
    Ok(bytes)
}

fn read_input_file(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| KeymanError::Io("cannot read input file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| KeymanError::Io("cannot inspect input file"))?;
    if metadata.len() > MAX_CRYPTO_INPUT {
        return Err(KeymanError::Input("input exceeds the supported size limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CRYPTO_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| KeymanError::Io("cannot read input file"))?;
    if bytes.len() as u64 > MAX_CRYPTO_INPUT {
        return Err(KeymanError::Input("input exceeds the supported size limit"));
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(u64, u64)> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| KeymanError::Io("cannot create key file"))?;
    let identity = match file.metadata() {
        Ok(metadata) => (metadata.dev(), metadata.ino()),
        Err(_) => {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(KeymanError::Io("cannot inspect key file"));
        }
    };
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        let _ = fs::remove_file(path);
        return Err(KeymanError::Io("cannot write key file"));
    }
    Ok(identity)
}

fn random_hex(bytes_len: usize) -> Result<String> {
    let mut bytes = vec![0u8; bytes_len];
    getrandom::getrandom(&mut bytes).map_err(|_| KeymanError::Crypto)?;
    let mut result = String::with_capacity(bytes_len * 2);
    for byte in &bytes {
        use std::fmt::Write as FmtWrite;
        let _ = write!(&mut result, "{byte:02x}");
    }
    bytes.zeroize();
    Ok(result)
}

fn write_atomic_with_identity(path: &Path, bytes: &[u8]) -> Result<(u64, u64)> {
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(KeymanError::Io("output directory does not exist"));
    }

    let mut temporary = None;
    for _ in 0..8 {
        let name = format!(".keyman-{}.tmp", random_hex(12)?);
        let candidate = parent.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        match options.open(&candidate) {
            Ok(mut file) => {
                let identity = match file.metadata() {
                    Ok(metadata) => (metadata.dev(), metadata.ino()),
                    Err(_) => {
                        drop(file);
                        let _ = fs::remove_file(&candidate);
                        return Err(KeymanError::Io("cannot inspect output file"));
                    }
                };
                if file.write_all(bytes).is_err() || file.sync_all().is_err() {
                    let _ = fs::remove_file(&candidate);
                    return Err(KeymanError::Io("cannot write output file"));
                }
                temporary = Some((candidate, identity));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(KeymanError::Io("cannot create output file")),
        }
    }
    let (temporary, identity) = temporary.ok_or(KeymanError::Io("cannot allocate output file"))?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            let _ = fs::remove_file(&temporary);
            return Err(KeymanError::Io("cannot replace output file"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            let _ = fs::remove_file(&temporary);
            return Err(KeymanError::Io("cannot inspect output file"));
        }
    }
    if fs::rename(&temporary, path).is_err() {
        let _ = fs::remove_file(temporary);
        return Err(KeymanError::Io("cannot replace output file"));
    }
    if let Ok(directory) = File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(identity)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic_with_identity(path, bytes).map(|_| ())
}

fn derive_key_iv(password: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    let mut derived = [0u8; 48];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, PBKDF2_ROUNDS, &mut derived);
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&derived[..32]);
    iv.copy_from_slice(&derived[32..]);
    derived.zeroize();
    (key, iv)
}

fn encrypt_blob(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_CRYPTO_INPUT as usize {
        return Err(KeymanError::Input("input exceeds the supported size limit"));
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| KeymanError::Crypto)?;
    let (key, iv) = derive_key_iv(password, &salt);
    let key = Zeroizing::new(key);
    let iv = Zeroizing::new(iv);
    let mut buffer = Zeroizing::new(vec![0u8; plaintext.len() + AES_BLOCK_LEN]);
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let encrypted = Aes256CbcEncryptor::new_from_slices(key.as_ref(), iv.as_ref())
        .map_err(|_| KeymanError::Crypto)?
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|_| KeymanError::Crypto)?;
    let mut output = Vec::with_capacity(16 + encrypted.len());
    output.extend_from_slice(b"Salted__");
    output.extend_from_slice(&salt);
    output.extend_from_slice(encrypted);
    Ok(output)
}

fn decrypt_blob(password: &[u8], encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted.len() > MAX_ENCRYPTED_FILE as usize
        || encrypted.len() < 16 + AES_BLOCK_LEN
        || (encrypted.len() - 16) % AES_BLOCK_LEN != 0
        || &encrypted[..8] != b"Salted__"
    {
        return Err(KeymanError::Crypto);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&encrypted[8..16]);
    let (key, iv) = derive_key_iv(password, &salt);
    let key = Zeroizing::new(key);
    let iv = Zeroizing::new(iv);
    let mut buffer = Zeroizing::new(encrypted[16..].to_vec());
    let plaintext = Aes256CbcDecryptor::new_from_slices(key.as_ref(), iv.as_ref())
        .map_err(|_| KeymanError::Crypto)?
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| KeymanError::Crypto)?;
    let result = Zeroizing::new(plaintext.to_vec());
    Ok(result)
}

fn validate_service(service: &str, reserve_suite: bool) -> Result<()> {
    if service.is_empty()
        || service.len() > MAX_SERVICE_NAME
        || !service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || (reserve_suite && service == "service_suite")
    {
        return Err(KeymanError::Input(
            "service name must be safe ASCII letters, digits, or underscores",
        ));
    }
    Ok(())
}

fn validate_field_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_FIELD_VALUE || value.contains(&0) || value.contains(&b'\n') {
        return Err(KeymanError::Input(
            "credential field exceeds the supported format",
        ));
    }
    Ok(())
}

fn format_credentials(username: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    validate_field_value(username)?;
    validate_field_value(password)?;
    let total = b"username=\"\"\npassword=\"\"\n".len() + username.len() + password.len();
    if total > MAX_CREDENTIAL_PLAINTEXT {
        return Err(KeymanError::Input(
            "credential input exceeds the supported size limit",
        ));
    }
    let mut content = Zeroizing::new(Vec::with_capacity(total));
    content.extend_from_slice(b"username=\"");
    content.extend_from_slice(username);
    content.extend_from_slice(b"\"\npassword=\"");
    content.extend_from_slice(password);
    content.extend_from_slice(b"\"\n");
    Ok(content)
}

fn extract_quoted_field(plaintext: &[u8], field: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if plaintext.contains(&0) {
        return Err(KeymanError::Crypto);
    }
    let start = plaintext
        .windows(field.len())
        .position(|window| window == field)
        .ok_or(KeymanError::Crypto)?
        + field.len();
    let quote_start = plaintext[start..]
        .iter()
        .position(|byte| *byte == b'"')
        .ok_or(KeymanError::Crypto)?
        + start
        + 1;
    let end = plaintext[quote_start..]
        .iter()
        .position(|byte| *byte == b'"')
        .ok_or(KeymanError::Crypto)?
        + quote_start;
    let value = &plaintext[quote_start..end];
    if value.len() > MAX_FIELD_VALUE {
        return Err(KeymanError::Crypto);
    }
    Ok(Zeroizing::new(value.to_vec()))
}

fn suite_password(paths: &Paths, skeleton: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let encrypted = paths.read_key("service_suite")?;
    let plaintext = decrypt_blob(skeleton, &encrypted)?;
    extract_quoted_field(&plaintext, b"password=")
}

fn encrypt_service_key(paths: &Paths, service: &str, content: &[u8]) -> Result<()> {
    let skeleton = paths.read_skeleton()?;
    let suite = suite_password(paths, &skeleton)?;
    let encrypted = encrypt_blob(&suite, content)?;
    paths.write_key(service, &encrypted)
}

fn decrypt_service_key(paths: &Paths, service: &str) -> Result<Zeroizing<Vec<u8>>> {
    let encrypted = paths.read_key(service)?;
    if service == "service_suite" {
        let skeleton = paths.read_skeleton()?;
        decrypt_blob(&skeleton, &encrypted)
    } else {
        let skeleton = paths.read_skeleton()?;
        let suite = suite_password(paths, &skeleton)?;
        decrypt_blob(&suite, &encrypted)
    }
}

fn parse_config(data: &[u8]) -> Result<Vec<&[u8]>> {
    if data.len() as u64 > MAX_CRYPTO_INPUT || data.contains(&0) {
        return Err(KeymanError::Input(
            "input exceeds the supported size limit or contains invalid bytes",
        ));
    }
    let mut lines = Vec::new();
    for line in data.split(|byte| *byte == b'\n') {
        if line.len() > MAX_C_LINE {
            return Err(KeymanError::Input(
                "input line exceeds the supported size limit",
            ));
        }
        lines.push(line);
    }
    Ok(lines)
}

fn parse_create_input(path: &Path) -> Result<(String, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {
    let data = Zeroizing::new(read_input_file(path)?);
    let mut service: Option<String> = None;
    let mut username: Option<Zeroizing<Vec<u8>>> = None;
    let mut password: Option<Zeroizing<Vec<u8>>> = None;
    for line in parse_config(&data)? {
        if let Some(value) = line.strip_prefix(b"service=") {
            service = Some(
                std::str::from_utf8(value)
                    .map_err(|_| KeymanError::Input("input contains an invalid service name"))?
                    .to_owned(),
            );
        } else if let Some(value) = line.strip_prefix(b"username=") {
            username = Some(Zeroizing::new(value.to_vec()));
        } else if let Some(value) = line.strip_prefix(b"password=") {
            password = Some(Zeroizing::new(value.to_vec()));
        }
    }
    let service = service.ok_or(KeymanError::Input("input is missing service"))?;
    validate_service(&service, true)?;
    let username = username.ok_or(KeymanError::Input("input is missing username"))?;
    let password = password.ok_or(KeymanError::Input("input is missing password"))?;
    validate_field_value(&username)?;
    validate_field_value(&password)?;
    Ok((service, username, password))
}

fn parse_decrypt_input(path: &Path) -> Result<String> {
    let data = read_input_file(path)?;
    for line in parse_config(&data)? {
        if let Some(value) = line.strip_prefix(b"service=") {
            let service = std::str::from_utf8(value)
                .map_err(|_| KeymanError::Input("input contains an invalid service name"))?
                .to_owned();
            validate_service(&service, false)?;
            return Ok(service);
        }
    }
    Err(KeymanError::Input("input is missing service"))
}

fn parse_reencrypt_input(path: &Path) -> Result<(String, Zeroizing<Vec<u8>>)> {
    let data = Zeroizing::new(read_input_file(path)?);
    let mut service: Option<String> = None;
    let mut password: Option<Zeroizing<Vec<u8>>> = None;
    for line in parse_config(&data)? {
        if let Some(value) = line.strip_prefix(b"service=") {
            service = Some(
                std::str::from_utf8(value)
                    .map_err(|_| KeymanError::Input("input contains an invalid service name"))?
                    .to_owned(),
            );
        } else if let Some(value) = line.strip_prefix(b"new_password=") {
            password = Some(Zeroizing::new(value.to_vec()));
        }
    }
    let service = service.ok_or(KeymanError::Input("input is missing service"))?;
    validate_service(&service, true)?;
    let password = password.ok_or(KeymanError::Input("input is missing new_password"))?;
    validate_field_value(&password)?;
    Ok((service, password))
}

fn crypto_create(paths: &Paths, input_path: &Path) -> Result<()> {
    let (service, username, password) = parse_create_input(input_path)?;
    let content = format_credentials(&username, &password)?;
    encrypt_service_key(paths, &service, &content)
}

fn crypto_decrypt(paths: &Paths, input_path: &Path, output_path: &Path) -> Result<()> {
    let service = parse_decrypt_input(input_path)?;
    let plaintext = decrypt_service_key(paths, &service)?;
    write_atomic(output_path, &plaintext)
}

fn crypto_reencrypt(paths: &Paths, input_path: &Path) -> Result<()> {
    let (service, new_password) = parse_reencrypt_input(input_path)?;
    let original = decrypt_service_key(paths, &service)?;
    let username = extract_quoted_field(&original, b"username=")?;
    let password = extract_quoted_field(&original, b"password=")?;
    let content = format_credentials(&username, &password)?;
    let encrypted = encrypt_blob(&new_password, &content)?;
    paths.write_key(&service, &encrypted)
}

fn crypto_encrypt_suite(paths: &Paths, input_path: &Path) -> Result<()> {
    let content = Zeroizing::new(read_input_file(input_path)?);
    let skeleton = paths.read_skeleton()?;
    let encrypted = encrypt_blob(&skeleton, &content)?;
    let suite_path = paths.check_fixed_parent("vault/.keys/service_suite.key")?;
    write_atomic(&suite_path, &encrypted)
}

fn generate_skeleton_secret() -> Result<Zeroizing<Vec<u8>>> {
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|_| KeymanError::Crypto)?;
    let mut generated = Zeroizing::new(Vec::with_capacity(64));
    for byte in random {
        generated.push(PASSWORD_ALPHABET[(byte & 0x0f) as usize]);
    }
    random.zeroize();
    Ok(generated)
}

fn native_init(paths: &Paths) -> Result<Value> {
    paths.ensure_key_directories()?;
    let skeleton_path = paths.skeleton();
    let suite_path = paths.suite_key();
    let skeleton_exists = match fs::symlink_metadata(&skeleton_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(KeymanError::Io("skeleton key path is not a regular file"));
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(KeymanError::Io("cannot inspect skeleton key")),
    };
    let suite_exists = match fs::symlink_metadata(&suite_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(KeymanError::Io(
                "service suite key path is not a regular file",
            ));
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(KeymanError::Io("cannot inspect service suite key")),
    };
    if !skeleton_exists && suite_exists {
        return Err(KeymanError::Crypto);
    }

    let mut created_skeleton = false;
    if !skeleton_exists {
        let mut bytes = generate_skeleton_secret()?;
        bytes.push(b'\n');
        write_new_file(&skeleton_path, &bytes)?;
        created_skeleton = true;
    }
    let skeleton = paths.read_skeleton()?;

    let mut created_suite = false;
    if !suite_exists {
        let suite_content = format_credentials(b"service_suite", &skeleton)?;
        let encrypted = encrypt_blob(&skeleton, &suite_content)?;
        write_new_file(&suite_path, &encrypted)?;
        created_suite = true;
    }

    let mut receipt = receipt_base("init");
    receipt.insert("created_skeleton".into(), Value::Bool(created_skeleton));
    receipt.insert("created_service_suite".into(), Value::Bool(created_suite));
    receipt.insert("secret_free".into(), Value::Bool(true));
    Ok(Value::Object(receipt))
}

fn native_newkey(paths: &Paths, service: &str, username: &str, password: &str) -> Result<Value> {
    validate_service(service, true)?;
    let content = format_credentials(username.as_bytes(), password.as_bytes())?;
    encrypt_service_key(paths, service, &content)?;
    let mut receipt = receipt_base("newkey");
    receipt.insert("service".into(), Value::String(service.to_owned()));
    receipt.insert("secret_free".into(), Value::Bool(true));
    Ok(Value::Object(receipt))
}

fn native_delete(paths: &Paths, service: &str) -> Result<Value> {
    validate_service(service, false)?;
    let path = paths.checked_key_path(service)?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| KeymanError::Io("key file does not exist"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KeymanError::Io("key file is not a regular file"));
    }
    fs::remove_file(&path).map_err(|_| KeymanError::Io("cannot delete key file"))?;
    if let Some(parent) = path.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    let mut receipt = receipt_base("delete");
    receipt.insert("service".into(), Value::String(service.to_owned()));
    receipt.insert("deleted".into(), Value::Bool(true));
    receipt.insert("secret_free".into(), Value::Bool(true));
    Ok(Value::Object(receipt))
}

fn secure_remove_if_identity(path: &Path, device: u64, inode: u64) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(KeymanError::Io("cannot inspect export file")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KeymanError::Io("export path is not a regular file"));
    }
    if metadata.dev() != device || metadata.ino() != inode {
        return Ok(false);
    }
    let mut options = OpenOptions::new();
    options.write(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|_| KeymanError::Io("cannot clear export file"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| KeymanError::Io("cannot inspect export file"))?;
    if opened_metadata.dev() != device || opened_metadata.ino() != inode {
        return Ok(false);
    }
    let mut remaining = opened_metadata.size();
    let zeros = [0u8; 4096];
    while remaining > 0 {
        let amount = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..amount])
            .map_err(|_| KeymanError::Io("cannot clear export file"))?;
        remaining -= amount as u64;
    }
    file.sync_all()
        .map_err(|_| KeymanError::Io("cannot clear export file"))?;
    drop(file);
    let current = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(_) => return Err(KeymanError::Io("cannot inspect export file")),
    };
    if current.file_type().is_symlink() || !current.is_file() {
        return Err(KeymanError::Io("export path is not a regular file"));
    }
    if current.dev() != device || current.ino() != inode {
        return Ok(false);
    }
    fs::remove_file(path).map_err(|_| KeymanError::Io("cannot remove export file"))?;
    Ok(true)
}

fn schedule_export_cleanup(service: &str, device: u64, inode: u64) -> Result<()> {
    let executable =
        env::current_exe().map_err(|_| KeymanError::Io("cannot start export cleanup"))?;
    Command::new(executable)
        .arg("__cleanup_export")
        .arg(service)
        .arg(device.to_string())
        .arg(inode.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| KeymanError::Io("cannot start export cleanup"))?;
    Ok(())
}

fn native_export(paths: &Paths, service: &str) -> Result<Value> {
    validate_service(service, false)?;
    let plaintext = decrypt_service_key(paths, service)?;
    let exchange = paths.exchange_directory()?;
    let output = exchange.join(service);
    let (device, inode) = write_atomic_with_identity(&output, &plaintext)?;
    if let Err(error) = schedule_export_cleanup(service, device, inode) {
        let _ = secure_remove_if_identity(&output, device, inode);
        return Err(error);
    }
    let mut receipt = receipt_base("export");
    receipt.insert(
        "exchange_file".into(),
        Value::String(output.to_string_lossy().into_owned()),
    );
    receipt.insert(
        "cleanup_after_seconds".into(),
        Value::from(CLEANUP_DELAY_SECONDS),
    );
    receipt.insert("secret_free".into(), Value::Bool(true));
    Ok(Value::Object(receipt))
}

fn cleanup_export(paths: &Paths, service: &str, device: u64, inode: u64) -> Result<()> {
    validate_service(service, false)?;
    thread::sleep(Duration::from_secs(CLEANUP_DELAY_SECONDS));
    if !paths.rooted && !exchange_tmpfs_is_mounted() {
        return Ok(());
    }
    let relative = format!("mnt/keyexchange/{service}");
    let path = paths.check_fixed_parent(&relative)?;
    secure_remove_if_identity(&path, device, inode).map(|_| ())
}

fn native_rotate_suite(paths: &Paths, new_password: Option<&str>) -> Result<Value> {
    paths.ensure_key_directories()?;
    let skeleton = paths.read_skeleton()?;
    let current_password = suite_password(paths, &skeleton)?;
    let generated_password;
    let next_password: Zeroizing<Vec<u8>> = match new_password {
        Some(value) => {
            validate_field_value(value.as_bytes())?;
            if value.is_empty() {
                return Err(KeymanError::Input("new suite password must not be empty"));
            }
            Zeroizing::new(value.as_bytes().to_vec())
        }
        None => {
            generated_password = generate_skeleton_secret()?;
            Zeroizing::new(generated_password.to_vec())
        }
    };

    let vault = paths.vault();
    let entries = fs::read_dir(&vault).map_err(|_| KeymanError::Io("cannot list service keys"))?;
    let mut service_paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| KeymanError::Io("cannot list service keys"))?;
        let name = entry.file_name();
        let Some(filename) = name.to_str() else {
            continue;
        };
        let Some(service) = filename.strip_suffix(".key") else {
            continue;
        };
        if service == "service_suite" {
            continue;
        }
        validate_service(service, true)?;
        let file_type = entry
            .file_type()
            .map_err(|_| KeymanError::Io("cannot inspect service key"))?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(KeymanError::Io("service key is not a regular file"));
        }
        service_paths.push((service.to_owned(), entry.path()));
    }
    service_paths.sort_by(|left, right| left.0.cmp(&right.0));

    let mut updates: Vec<(PathBuf, Vec<u8>, Vec<u8>)> = Vec::with_capacity(service_paths.len() + 1);
    for (_, path) in service_paths {
        let old_encrypted =
            read_regular_file(&path, MAX_ENCRYPTED_FILE, "cannot read service key")?;
        let plaintext = decrypt_blob(&current_password, &old_encrypted)?;
        let encrypted = encrypt_blob(&next_password, &plaintext)?;
        updates.push((path, old_encrypted, encrypted));
    }

    let suite_path = paths.suite_key();
    let old_suite_encrypted = read_regular_file(
        &suite_path,
        MAX_ENCRYPTED_FILE,
        "cannot read service suite key",
    )?;
    let new_suite_content = format_credentials(b"service_suite", &next_password)?;
    let new_suite_encrypted = encrypt_blob(&skeleton, &new_suite_content)?;
    updates.push((suite_path, old_suite_encrypted, new_suite_encrypted));

    let service_count = updates.len().saturating_sub(1);
    let mut changed = 0usize;
    for (path, _old, new) in &updates {
        if let Err(error) = write_atomic(path, new) {
            let mut restore_failed = false;
            for (restore_path, old, _) in updates[..changed].iter().rev() {
                if write_atomic(restore_path, old).is_err() {
                    restore_failed = true;
                }
            }
            return if restore_failed {
                Err(KeymanError::Io(
                    "suite rotation failed and rollback was incomplete",
                ))
            } else {
                Err(error)
            };
        }
        changed += 1;
    }

    let mut receipt = receipt_base("rotate-suite");
    receipt.insert("rewrapped_services".into(), Value::from(service_count));
    receipt.insert("secret_free".into(), Value::Bool(true));
    Ok(Value::Object(receipt))
}

fn receipt_base(operation: &str) -> Map<String, Value> {
    let mut receipt = Map::new();
    receipt.insert("ok".into(), Value::Bool(true));
    receipt.insert("operation".into(), Value::String(operation.to_owned()));
    receipt
}

fn emit_receipt(value: Value) {
    println!("{value}");
}

fn usage() -> &'static str {
    "Usage: keyman crypto <create|reencrypt|encrypt_suite_key> <input_file> | keyman crypto decrypt <input_file> <output_file> | keyman <init|newkey|export|delete|rotate-suite> ..."
}

fn run_internal_cleanup(args: &[String]) -> Result<()> {
    if args.len() != 4 {
        return Err(KeymanError::Usage("invalid cleanup arguments"));
    }
    let paths = Paths::from_environment()?;
    let device = args[2]
        .parse::<u64>()
        .map_err(|_| KeymanError::Usage("invalid cleanup arguments"))?;
    let inode = args[3]
        .parse::<u64>()
        .map_err(|_| KeymanError::Usage("invalid cleanup arguments"))?;
    cleanup_export(&paths, &args[1], device, inode)
}

fn run_crypto(paths: &Paths, args: &[String]) -> Result<()> {
    let Some(verb) = args.first().map(String::as_str) else {
        return Err(KeymanError::Usage("missing crypto verb"));
    };
    match verb {
        "create" if args.len() == 2 => {
            let input = paths.argument_path(&args[1])?;
            crypto_create(paths, &input)
        }
        "decrypt" if args.len() == 3 => {
            if args[2].as_bytes().len() >= MAX_EXPLICIT_OUTPUT_PATH {
                return Err(KeymanError::Input(
                    "output path exceeds the supported size limit",
                ));
            }
            let input = paths.argument_path(&args[1])?;
            let output = paths.argument_path(&args[2])?;
            crypto_decrypt(paths, &input, &output)
        }
        "reencrypt" if args.len() == 2 => {
            let input = paths.argument_path(&args[1])?;
            crypto_reencrypt(paths, &input)
        }
        "encrypt_suite_key" if args.len() == 2 => {
            let input = paths.argument_path(&args[1])?;
            crypto_encrypt_suite(paths, &input)
        }
        "create" | "decrypt" | "reencrypt" | "encrypt_suite_key" => {
            Err(KeymanError::Usage("invalid crypto arguments"))
        }
        _ => Err(KeymanError::Usage("unknown crypto verb")),
    }
}

fn run(args: &mut [String]) -> Result<()> {
    if args.first().is_some_and(|arg| arg == "__cleanup_export") {
        return run_internal_cleanup(args);
    }
    if args.is_empty() {
        return Err(KeymanError::Usage(usage()));
    }
    if args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
        println!("{}", usage());
        return Ok(());
    }
    let paths = Paths::from_environment()?;
    if args[0] == "crypto" {
        return run_crypto(&paths, &args[1..]);
    }
    if matches!(
        args[0].as_str(),
        "create" | "decrypt" | "reencrypt" | "encrypt_suite_key"
    ) {
        return run_crypto(&paths, args);
    }
    match args[0].as_str() {
        "init" if args.len() == 1 => {
            let receipt = native_init(&paths)?;
            emit_receipt(receipt);
            Ok(())
        }
        "newkey" if args.len() == 4 => {
            let receipt = native_newkey(&paths, &args[1], &args[2], &args[3])?;
            emit_receipt(receipt);
            Ok(())
        }
        "export" if args.len() == 2 => {
            let receipt = native_export(&paths, &args[1])?;
            emit_receipt(receipt);
            Ok(())
        }
        "delete" if args.len() == 2 => {
            let receipt = native_delete(&paths, &args[1])?;
            emit_receipt(receipt);
            Ok(())
        }
        "rotate-suite" if args.len() == 1 || args.len() == 2 => {
            let receipt = native_rotate_suite(&paths, args.get(1).map(String::as_str))?;
            emit_receipt(receipt);
            Ok(())
        }
        "init" | "newkey" | "export" | "delete" | "rotate-suite" => {
            Err(KeymanError::Usage("invalid arguments"))
        }
        _ => Err(KeymanError::Usage(usage())),
    }
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let result = run(&mut args);
    for argument in &mut args {
        argument.zeroize();
    }
    if let Err(error) = result {
        eprintln!("ERROR: {}", error.message());
        std::process::exit(error.exit_code());
    }
}
