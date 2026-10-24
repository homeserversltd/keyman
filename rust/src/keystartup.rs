//! Additive, opt-in provisioning. No shell/Python compatibility path is called.
use crate::{
    crown::ExchangeSession, decrypt_blob, emit_receipt, encrypt_blob, format_credentials,
    generate_skeleton_secret, read_regular_file, write_atomic, write_new_exclusive, KeymanError,
    Paths, Result,
};
use serde_json::{json, Value};
use std::env;
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

#[derive(Default)]
struct Progress {
    created_skeleton: bool,
    created_service_suite: bool,
    created_nas: bool,
    owner_password_set: bool,
    owner_password_verified: bool,
    owner_password_skipped_rooted: bool,
    owner_password_skipped_flag: bool,
    deploy_file_written: bool,
    verified: bool,
}

impl Progress {
    fn receipt(&self, error: Option<&str>) -> Value {
        json!({
            "ok": error.is_none(), "operation": "keystartup", "secret_free": true,
            "created_skeleton": self.created_skeleton,
            "created_service_suite": self.created_service_suite,
            "created_nas": self.created_nas,
            "owner_password_set": self.owner_password_set,
            "owner_password_verified": self.owner_password_verified,
            "owner_password_skipped_rooted": self.owner_password_skipped_rooted,
            "owner_password_skipped_flag": self.owner_password_skipped_flag,
            "deploy_file_written": self.deploy_file_written,
            "verified": self.verified, "first_missing_signal": error,
        })
    }
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let mut progress = Progress::default();
    let result = (|| {
        let automated = args.iter().any(|arg| arg == "--automated")
            || env::var_os("AUTOMATED_SETUP").is_some_and(|value| value == "1");
        // This guard precedes even path resolution: refusal cannot create anything.
        if !automated {
            eprintln!("WARNING: KEYSTARTUP REFUSED! By default, this run would OVERWRITE the owner account's password with the skeleton key. --keep-owner-password skips the owner/deploy steps but does not authorize provisioning. Allow this only intentionally with --automated (or AUTOMATED_SETUP=1).");
            return Err(KeymanError::Input("keystartup-automated-flag-required"));
        }
        let mut automated_argument = false;
        let mut keep_owner_password = false;
        for arg in &args[1..] {
            match arg.as_str() {
                "--automated" if !automated_argument => automated_argument = true,
                "--keep-owner-password" if !keep_owner_password => keep_owner_password = true,
                _ => return Err(KeymanError::Usage("keystartup-arguments-invalid")),
            }
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err(KeymanError::Io("keystartup-requires-root"));
        }
        let paths = Paths::from_environment()?;
        provision(&paths, keep_owner_password, &mut progress)
    })();
    match result {
        Ok(()) => {
            emit_receipt(progress.receipt(None));
            Ok(())
        }
        Err(error) => {
            emit_receipt(progress.receipt(Some(error.message())));
            eprintln!("ERROR: {}", error.message());
            Err(KeymanError::Reported(error.exit_code()))
        }
    }
}

fn regular_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(KeymanError::Io("keystartup-key-path-not-regular"))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(KeymanError::Io("keystartup-key-inspection-failed")),
    }
}

fn exclusive_lock(file: &File) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(KeymanError::Io("keystartup-custody-busy"));
    }
    Ok(())
}

fn ensure_credential(paths: &Paths, name: &str, skeleton: &[u8], created: &mut bool) -> Result<()> {
    let path = paths.checked_key_path(name)?;
    let content = format_credentials(name.as_bytes(), skeleton)?;
    if !regular_exists(&path)? {
        let encrypted = encrypt_blob(skeleton, &content)?;
        write_new_exclusive(&path, &encrypted, "keystartup-key-already-exists")?;
        *created = true;
    }
    // Compare the whole canonical record, not just the presence of a password field.
    let encrypted = paths.read_key(name)?;
    if decrypt_blob(skeleton, &encrypted)?.as_slice() != content.as_slice() {
        return Err(KeymanError::Crypto);
    }
    Ok(())
}

fn provision(paths: &Paths, keep_owner_password: bool, progress: &mut Progress) -> Result<()> {
    paths.ensure_key_directories()?;
    let key_directory = File::open(paths.fixed("root/key"))
        .map_err(|_| KeymanError::Io("keystartup-key-directory-unavailable"))?;
    exclusive_lock(&key_directory)?;
    let skeleton_exists = regular_exists(&paths.skeleton())?;
    let suite_exists = regular_exists(&paths.suite_key())?;
    let nas_exists = regular_exists(&paths.checked_key_path("nas")?)?;
    if !skeleton_exists && (suite_exists || nas_exists) {
        return Err(KeymanError::Input(
            "keystartup-existing-key-without-skeleton",
        ));
    }
    for directory in [paths.fixed("root/key"), paths.vault()] {
        if fs::metadata(&directory)
            .map_err(|_| KeymanError::Io("keystartup-directory-inspection-failed"))?
            .mode()
            & 0o7777
            != 0o700
        {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| KeymanError::Io("keystartup-directory-permissions-failed"))?;
        }
    }
    if !skeleton_exists {
        let mut secret = generate_skeleton_secret()?;
        secret.push(b'\n');
        write_new_exclusive(
            &paths.skeleton(),
            &secret,
            "keystartup-skeleton-already-exists",
        )?;
        progress.created_skeleton = true;
    }
    let skeleton_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(paths.skeleton())
        .map_err(|_| KeymanError::Io("keystartup-skeleton-unavailable"))?;
    exclusive_lock(&skeleton_file)?;
    let mut skeleton = Zeroizing::new(read_regular_file(
        &paths.skeleton(),
        512,
        "keystartup-skeleton-unavailable",
    )?);
    while skeleton.last() == Some(&b'\n') {
        skeleton.pop();
    }
    if skeleton.is_empty()
        || skeleton.len() > 511
        || skeleton
            .iter()
            .any(|byte| matches!(*byte, 0 | b'\n' | b'\r' | b'"'))
    {
        return Err(KeymanError::Input("keystartup-skeleton-invalid"));
    }
    // Birth and tear down the installer's exchange tmpfs for this act only.
    // All credential plaintext stays in zeroizing memory, never on that tmpfs.
    let mut exchange = ExchangeSession::begin(paths).map_err(KeymanError::Io)?;
    let provision_result = (|| {
        ensure_credential(
            paths,
            "service_suite",
            &skeleton,
            &mut progress.created_service_suite,
        )?;
        ensure_credential(paths, "nas", &skeleton, &mut progress.created_nas)?;
        if keep_owner_password {
            progress.owner_password_skipped_flag = true;
        } else {
            set_owner_password(paths, &skeleton, progress)?;
            write_deploy_password(paths, &skeleton, &mut progress.deploy_file_written)?;
        }
        Ok(())
    })();
    // Cleanup errors must override success (and remain visible after partial writes).
    exchange.cleanup().map_err(KeymanError::Io)?;
    provision_result?;
    progress.verified = true;
    Ok(())
}

// Load the host's password verifier in process; no new linked runtime or helper
// executable is required. libxcrypt supplies crypt on the supported Linux bodies.
struct PasswordVerifier(*mut libc::c_void);

impl PasswordVerifier {
    fn load() -> Result<Self> {
        for name in [b"libcrypt.so.2\0".as_slice(), b"libcrypt.so.1\0".as_slice()] {
            let handle =
                unsafe { libc::dlopen(name.as_ptr().cast(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if !handle.is_null() {
                return Ok(Self(handle));
            }
        }
        Err(KeymanError::Io("keystartup-password-verifier-unavailable"))
    }

    fn matches(&self, paths: &Paths, password: &[u8]) -> Result<bool> {
        let shadow = Zeroizing::new(read_regular_file(
            &paths.check_fixed_parent("etc/shadow")?,
            1024 * 1024,
            "keystartup-owner-shadow-unavailable",
        )?);
        let row = shadow
            .split(|byte| *byte == b'\n')
            .find_map(|line| line.strip_prefix(b"owner:"))
            .ok_or(KeymanError::Io("keystartup-owner-account-missing"))?;
        let hash = row.split(|byte| *byte == b':').next().unwrap_or_default();
        if hash.is_empty() || matches!(hash[0], b'!' | b'*') {
            return Ok(false);
        }
        if hash.len() > 1024 || hash.contains(&0) {
            return Err(KeymanError::Input("keystartup-owner-shadow-invalid"));
        }
        let symbol = unsafe { libc::dlsym(self.0, b"crypt\0".as_ptr().cast()) };
        if symbol.is_null() {
            return Err(KeymanError::Io("keystartup-password-verifier-unavailable"));
        }
        type Crypt =
            unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::c_char;
        let crypt: Crypt = unsafe { std::mem::transmute(symbol) };
        let mut input = Zeroizing::new(password.to_vec());
        input.push(0);
        let mut setting = Zeroizing::new(hash.to_vec());
        setting.push(0);
        let output = unsafe { crypt(input.as_ptr().cast(), setting.as_ptr().cast()) };
        if output.is_null() {
            return Err(KeymanError::Io(
                "keystartup-owner-password-verification-failed",
            ));
        }
        let output_bytes = unsafe { CStr::from_ptr(output) }.to_bytes();
        let matches = output_bytes == hash;
        // crypt owns this static output; erase the result before unloading it.
        unsafe { std::ptr::write_bytes(output.cast::<u8>(), 0, output_bytes.len()) };
        Ok(matches)
    }
}

impl Drop for PasswordVerifier {
    fn drop(&mut self) {
        unsafe { libc::dlclose(self.0) };
    }
}

fn set_owner_password(paths: &Paths, skeleton: &[u8], progress: &mut Progress) -> Result<()> {
    let mut input = Zeroizing::new(Vec::with_capacity(skeleton.len() + 7));
    input.extend_from_slice(b"owner:");
    input.extend_from_slice(skeleton);
    input.push(b'\n');
    if paths.rooted {
        // Deliberately do not spawn even a prefixed host chpasswd in isolation.
        // The same bounded stdin payload is prepared, but no credential is changed.
        progress.owner_password_skipped_rooted = true;
        return Ok(());
    }
    let verifier = PasswordVerifier::load()?;
    if verifier.matches(paths, skeleton)? {
        progress.owner_password_verified = true;
        return Ok(());
    }
    let program = ["/usr/sbin/chpasswd", "/usr/bin/chpasswd"]
        .into_iter()
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o022 == 0
                    && metadata.mode() & 0o111 != 0
            })
        })
        .ok_or(KeymanError::Io("keystartup-chpasswd-unavailable"))?;
    let mut child = Command::new(program)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| KeymanError::Io("keystartup-chpasswd-spawn-failed"))?;
    let sent = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(&input).is_ok());
    let status = child
        .wait()
        .map_err(|_| KeymanError::Io("keystartup-chpasswd-wait-failed"))?;
    if !sent || !status.success() {
        return Err(KeymanError::Io("keystartup-owner-password-update-failed"));
    }
    progress.owner_password_set = true;
    if !verifier.matches(paths, skeleton)? {
        return Err(KeymanError::Io(
            "keystartup-owner-password-verification-failed",
        ));
    }
    progress.owner_password_verified = true;
    Ok(())
}

fn owner_ids(paths: &Paths) -> Result<(u32, u32)> {
    // Use the fixed-root account files, never host NSS for a scratch-root owner.
    let passwd = read_regular_file(
        &paths.check_fixed_parent("etc/passwd")?,
        1024 * 1024,
        "keystartup-owner-account-unavailable",
    )?;
    let group = read_regular_file(
        &paths.check_fixed_parent("etc/group")?,
        1024 * 1024,
        "keystartup-owner-group-unavailable",
    )?;
    let passwd = std::str::from_utf8(&passwd)
        .map_err(|_| KeymanError::Input("keystartup-owner-account-invalid"))?;
    let group = std::str::from_utf8(&group)
        .map_err(|_| KeymanError::Input("keystartup-owner-group-invalid"))?;
    let uid = passwd
        .lines()
        .find(|line| line.starts_with("owner:"))
        .and_then(|line| line.split(':').nth(2))
        .and_then(|field| field.parse().ok())
        .ok_or(KeymanError::Input("keystartup-owner-account-missing"))?;
    let gid = group
        .lines()
        .find(|line| line.starts_with("owner:"))
        .and_then(|line| line.split(':').nth(2))
        .and_then(|field| field.parse().ok())
        .ok_or(KeymanError::Input("keystartup-owner-group-missing"))?;
    Ok((uid, gid))
}

fn write_deploy_password(paths: &Paths, skeleton: &[u8], written: &mut bool) -> Result<()> {
    let deploy = paths.fixed("deploy");
    match fs::symlink_metadata(&deploy) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        _ => return Err(KeymanError::Io("keystartup-deploy-directory-unsafe")),
    }
    let path = paths.check_fixed_parent("deploy/password.txt")?;
    let (uid, gid) = owner_ids(paths)?;
    let mut content = Zeroizing::new(skeleton.to_vec());
    content.push(b'\n');
    let exists = regular_exists(&path)?;
    let content_matches = exists
        && Zeroizing::new(read_regular_file(
            &path,
            512,
            "keystartup-deploy-read-failed",
        )?)
        .as_slice()
            == content.as_slice();
    if !content_matches {
        write_atomic(&path, &content)?;
        *written = true;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| KeymanError::Io("keystartup-deploy-open-failed"))?;
    let metadata = file
        .metadata()
        .map_err(|_| KeymanError::Io("keystartup-deploy-inspection-failed"))?;
    let ownership_changed = metadata.uid() != uid || metadata.gid() != gid;
    if ownership_changed && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(KeymanError::Io("keystartup-deploy-owner-failed"));
    }
    *written |= ownership_changed;
    let mode_changed = metadata.mode() & 0o7777 != 0o700;
    if mode_changed {
        file.set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| KeymanError::Io("keystartup-deploy-permissions-failed"))?;
        *written = true;
    }
    if *written {
        file.sync_all()
            .map_err(|_| KeymanError::Io("keystartup-deploy-sync-failed"))?;
    }
    let final_metadata = file
        .metadata()
        .map_err(|_| KeymanError::Io("keystartup-deploy-inspection-failed"))?;
    if final_metadata.uid() != uid
        || final_metadata.gid() != gid
        || final_metadata.mode() & 0o7777 != 0o700
    {
        return Err(KeymanError::Io(
            "keystartup-deploy-metadata-readback-failed",
        ));
    }
    if Zeroizing::new(read_regular_file(
        &path,
        512,
        "keystartup-deploy-readback-failed",
    )?)
    .as_slice()
        != content.as_slice()
    {
        return Err(KeymanError::Io("keystartup-deploy-readback-failed"));
    }
    Ok(())
}
