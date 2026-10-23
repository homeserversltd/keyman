use crate::{
    decrypt_blob, decrypt_service_key, encrypt_blob, extract_quoted_field, format_credentials,
    native_export_to_directory, native_newkey, read_regular_file, secure_remove_if_identity,
    write_atomic, Paths, SecretMemfd,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::env;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use zeroize::{Zeroize, Zeroizing};

const MAX_CROWN_INPUT: u64 = 64 * 1024;
const MAX_KEY_FILE: u64 = 1024 * 1024;

pub(crate) fn is_verb(value: &str) -> bool {
    matches!(
        value,
        "key-status" | "create-key" | "update-key" | "admin-password"
    )
}

pub(crate) fn run(args: &[String]) -> i32 {
    let operation = args.first().map(String::as_str).unwrap_or("unknown");
    let receipt = match operation {
        "key-status" => key_status(args),
        "create-key" => create_key(args),
        "update-key" => update_key(args),
        "admin-password" => admin_password(args),
        _ => failure_receipt(
            "unknown",
            false,
            false,
            "keyman-operation-invalid",
            json!({}),
        ),
    };
    let ok = receipt.get("ok").and_then(Value::as_bool).unwrap_or(false);
    println!("{receipt}");
    if ok {
        0
    } else {
        1
    }
}

fn receipt(
    operation: &str,
    ok: bool,
    planned: bool,
    changed: bool,
    details: Value,
    signal: Option<&str>,
) -> Value {
    json!({
        "ok": ok,
        "operation": operation,
        "planned": planned,
        "changed": changed,
        "details": details,
        "firstMissingSignal": signal,
    })
}

fn failure_receipt(
    operation: &str,
    planned: bool,
    changed: bool,
    signal: &str,
    details: Value,
) -> Value {
    receipt(operation, false, planned, changed, details, Some(signal))
}

fn success_receipt(operation: &str, planned: bool, changed: bool, details: Value) -> Value {
    receipt(operation, true, planned, changed, details, None)
}

fn paths() -> std::result::Result<Paths, &'static str> {
    let paths = Paths::from_environment().map_err(|_| "keyman-paths-unavailable")?;
    if paths.rooted && paths.root == Path::new("/") {
        return Err("keyman-fixture-root-refused");
    }
    Ok(paths)
}

struct SecretDocument(Value);

impl Drop for SecretDocument {
    fn drop(&mut self) {
        zeroize_json(&mut self.0);
    }
}

fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => {
            for item in items {
                zeroize_json(item);
            }
        }
        Value::Object(map) => {
            let owned = std::mem::take(map);
            for (mut key, mut value) in owned {
                key.zeroize();
                zeroize_json(&mut value);
            }
        }
        _ => {}
    }
}

fn read_secret_document() -> std::result::Result<SecretDocument, &'static str> {
    let stdin = std::io::stdin();
    let mut raw = Zeroizing::new(Vec::new());
    stdin
        .lock()
        .take(MAX_CROWN_INPUT + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "keyman-request-read-failed")?;
    if raw.len() as u64 > MAX_CROWN_INPUT {
        return Err("keyman-request-too-large");
    }
    let document =
        SecretDocument(serde_json::from_slice(&raw).map_err(|_| "keyman-request-invalid")?);
    if !document.0.is_object() {
        return Err("keyman-request-invalid");
    }
    Ok(document)
}

fn object(document: &SecretDocument) -> &Map<String, Value> {
    document.0.as_object().expect("validated JSON object")
}

fn planned_field(object: &Map<String, Value>) -> std::result::Result<bool, &'static str> {
    match object.get("planned") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err("keyman-planned-flag-invalid"),
    }
}

fn secret_field(
    object: &Map<String, Value>,
    name: &str,
    signal: &'static str,
) -> std::result::Result<Zeroizing<String>, &'static str> {
    let source = object.get(name).and_then(Value::as_str).ok_or(signal)?;
    Ok(Zeroizing::new(source.to_owned()))
}

fn validate_secret(value: &str, signal: &'static str) -> std::result::Result<(), &'static str> {
    if value.is_empty()
        || value.as_bytes().contains(&0)
        || value.as_bytes().contains(&b'\n')
        || value.as_bytes().contains(&b'\r')
        || value.as_bytes().contains(&b'"')
    {
        return Err(signal);
    }
    if value.len() > 511 {
        return Err(signal);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Strategy {
    SafeRotation,
    ReplacePrimary,
    FlexibleAddition,
}

impl Strategy {
    fn parse(value: &str) -> std::result::Result<Self, &'static str> {
        match value {
            "safe_rotation" => Ok(Self::SafeRotation),
            "replace_primary" => Ok(Self::ReplacePrimary),
            "flexible_addition" => Ok(Self::FlexibleAddition),
            _ => Err("keyman-strategy-invalid"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SafeRotation => "safe_rotation",
            Self::ReplacePrimary => "replace_primary",
            Self::FlexibleAddition => "flexible_addition",
        }
    }
}

fn parse_create_args(args: &[String]) -> std::result::Result<(String, Strategy), &'static str> {
    if args.len() != 5 || args[1] != "--target" || args[3] != "--strategy" {
        return Err("keyman-create-key-usage-invalid");
    }
    let target = args[2].as_str();
    if !matches!(target, "vault" | "external" | "both") {
        return Err("keyman-target-invalid");
    }
    Ok((target.to_owned(), Strategy::parse(&args[4])?))
}

fn parse_update_args(args: &[String]) -> std::result::Result<(Device, Strategy), &'static str> {
    if args.len() != 5 || args[1] != "--device" || args[3] != "--strategy" {
        return Err("keyman-update-key-usage-invalid");
    }
    let strategy = Strategy::parse(&args[4])?;
    let paths = paths()?;
    let device = device_node(&paths, &args[2])?;
    Ok((device, strategy))
}

fn parse_status_args(args: &[String]) -> std::result::Result<Option<String>, &'static str> {
    match args {
        [_] => Ok(None),
        [_, flag, device] if flag == "--device" => Ok(Some(device.clone())),
        _ => Err("keyman-key-status-usage-invalid"),
    }
}

fn device_node(paths: &Paths, supplied: &str) -> std::result::Result<Device, &'static str> {
    let input = Path::new(supplied);
    if !input.is_absolute() {
        return Err("keyman-device-path-invalid");
    }
    let mut components = input.components();
    if components.next() != Some(Component::RootDir)
        || components.next() != Some(Component::Normal(std::ffi::OsStr::new("dev")))
    {
        return Err("keyman-device-path-invalid");
    }
    for component in components {
        if !matches!(component, Component::Normal(_)) {
            return Err("keyman-device-path-invalid");
        }
    }
    let device_root = paths.root.join("dev");
    let device_root =
        fs::canonicalize(device_root).map_err(|_| "keyman-device-root-unavailable")?;
    if paths.rooted && !device_root.starts_with(&paths.root) {
        return Err("keyman-device-root-escape");
    }
    let candidate = paths.root.join(
        input
            .strip_prefix("/")
            .map_err(|_| "keyman-device-path-invalid")?,
    );
    let canonical = fs::canonicalize(&candidate).map_err(|_| "keyman-device-not-found")?;
    if !canonical.starts_with(&device_root) {
        return Err("keyman-device-root-escape");
    }
    let metadata = fs::metadata(&canonical).map_err(|_| "keyman-device-not-found")?;
    if !metadata.file_type().is_block_device() {
        return Err("keyman-device-not-block-node");
    }
    let logical = format!(
        "/{}",
        input
            .strip_prefix("/")
            .map_err(|_| "keyman-device-path-invalid")?
            .to_string_lossy()
    );
    if !logical.starts_with("/dev/") {
        return Err("keyman-device-root-escape");
    }
    Ok(Device {
        path: canonical,
        command_path: candidate,
        logical,
        rdev: metadata.rdev(),
    })
}

fn reported_device(paths: &Paths, reported: &str) -> std::result::Result<Device, &'static str> {
    let reported = reported.trim();
    if reported.starts_with("/dev/") {
        return device_node(paths, reported);
    }
    if paths.rooted {
        let root_prefix = paths.root.to_string_lossy();
        if let Some(logical) = reported.strip_prefix(root_prefix.as_ref()) {
            if logical.starts_with("/dev/") {
                return device_node(paths, logical);
            }
        }
    }
    Err("keyman-device-backing-invalid")
}

#[derive(Clone, Debug)]
struct Device {
    path: PathBuf,
    command_path: PathBuf,
    logical: String,
    rdev: u64,
}

fn command_output(
    command: &mut Command,
    signal: &'static str,
) -> std::result::Result<Output, &'static str> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| signal)
}

fn feed_secret(
    child: &mut Child,
    secret: &[u8],
    signal: &'static str,
) -> std::result::Result<(), &'static str> {
    let Some(mut input) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(signal);
    };
    if input.write_all(secret).is_err() {
        drop(input);
        let _ = child.kill();
        let _ = child.wait();
        return Err(signal);
    }
    drop(input);
    Ok(())
}

fn secret_command(
    command: &mut Command,
    secret: &[u8],
    signal: &'static str,
) -> std::result::Result<bool, &'static str> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| signal)?;
    feed_secret(&mut child, secret, signal)?;
    let status = child.wait().map_err(|_| signal)?;
    Ok(status.success())
}

fn test_passphrase(
    device: &Device,
    password: &[u8],
    slot: Option<u8>,
) -> std::result::Result<bool, &'static str> {
    let mut command = Command::new("cryptsetup");
    command.args(["open", "--test-passphrase"]);
    if let Some(slot) = slot {
        command.arg("--key-slot").arg(slot.to_string());
    }
    command.args(["--key-file", "-"]).arg(&device.path);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "keyman-device-auth-observation-failed")?;
    feed_secret(
        &mut child,
        password,
        "keyman-device-auth-observation-failed",
    )?;
    let status = child
        .wait()
        .map_err(|_| "keyman-device-auth-observation-failed")?;
    Ok(status.success())
}

fn test_passphrase_file(
    device: &Device,
    key_file: &Path,
    slot: Option<u8>,
) -> std::result::Result<bool, &'static str> {
    let mut command = Command::new("cryptsetup");
    command.args(["open", "--test-passphrase"]);
    if let Some(slot) = slot {
        command.arg("--key-slot").arg(slot.to_string());
    }
    command.args(["--key-file"]).arg(key_file).arg(&device.path);
    let output = command_output(&mut command, "keyman-device-auth-observation-failed")?;
    Ok(output.status.success())
}

fn test_auth_passphrase(
    device: &Device,
    password: &[u8],
    key_file: Option<&Path>,
    slot: Option<u8>,
) -> std::result::Result<bool, &'static str> {
    match key_file {
        Some(path) => test_passphrase_file(device, path, slot),
        None => test_passphrase(device, password, slot),
    }
}

#[derive(Clone, Debug)]
struct LuksSnapshot {
    total: u8,
    enabled: BTreeSet<u8>,
}

fn is_luks(device: &Device) -> std::result::Result<bool, &'static str> {
    let mut command = Command::new("cryptsetup");
    command.arg("isLuks").arg(&device.path);
    let output = command_output(&mut command, "keyman-device-observation-failed")?;
    if output.status.success() {
        return Ok(true);
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    Err("keyman-device-observation-failed")
}

fn inspect_luks(device: &Device) -> std::result::Result<Option<LuksSnapshot>, &'static str> {
    if !is_luks(device)? {
        return Ok(None);
    }
    let mut dump = Command::new("cryptsetup");
    dump.arg("luksDump").arg(&device.path);
    let output = command_output(&mut dump, "keyman-device-luks-dump-failed")?;
    if !output.status.success() {
        return Err("keyman-device-luks-dump-failed");
    }
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| "keyman-device-luks-dump-invalid")?;
    let version = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("Version:").map(str::trim))
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or("keyman-device-luks-version-unknown")?;
    match version {
        1 => parse_luks1_slots(text).map(|enabled| Some(LuksSnapshot { total: 8, enabled })),
        2 => {
            let mut metadata = Command::new("cryptsetup");
            metadata
                .args(["luksDump", "--dump-json-metadata"])
                .arg(&device.path);
            let output = command_output(&mut metadata, "keyman-device-luks-metadata-failed")?;
            if !output.status.success() {
                return Err("keyman-device-luks-metadata-failed");
            }
            let document: Value = serde_json::from_slice(&output.stdout)
                .map_err(|_| "keyman-device-luks-metadata-invalid")?;
            let keyslots = document
                .get("keyslots")
                .and_then(Value::as_object)
                .ok_or("keyman-device-luks-metadata-invalid")?;
            let mut enabled = BTreeSet::new();
            for slot in keyslots.keys() {
                let slot = slot
                    .parse::<u8>()
                    .map_err(|_| "keyman-device-luks-metadata-invalid")?;
                if slot >= 32 || !enabled.insert(slot) {
                    return Err("keyman-device-luks-metadata-invalid");
                }
            }
            Ok(Some(LuksSnapshot { total: 32, enabled }))
        }
        _ => Err("keyman-device-luks-version-unsupported"),
    }
}

fn parse_luks1_slots(text: &str) -> std::result::Result<BTreeSet<u8>, &'static str> {
    let mut seen = BTreeSet::new();
    let mut enabled = BTreeSet::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("Key Slot ") else {
            continue;
        };
        let Some((slot, status)) = rest.split_once(':') else {
            return Err("keyman-device-luks-metadata-invalid");
        };
        let slot = slot
            .trim()
            .parse::<u8>()
            .map_err(|_| "keyman-device-luks-metadata-invalid")?;
        if slot >= 8 || !seen.insert(slot) {
            return Err("keyman-device-luks-metadata-invalid");
        }
        match status.trim() {
            "ENABLED" => {
                enabled.insert(slot);
            }
            "DISABLED" => {}
            _ => return Err("keyman-device-luks-metadata-invalid"),
        }
    }
    if seen.len() != 8 || !(0..8).all(|slot| seen.contains(&slot)) {
        return Err("keyman-device-luks-metadata-invalid");
    }
    Ok(enabled)
}

fn slot_summary(snapshot: &LuksSnapshot) -> Value {
    let slots: Vec<Value> = (0..snapshot.total)
        .map(|slot| {
            json!({
                "slot": slot,
                "status": if snapshot.enabled.contains(&slot) { "enabled" } else { "disabled" }
            })
        })
        .collect();
    json!({
        "total": snapshot.total,
        "used": snapshot.enabled.len(),
        "available": usize::from(snapshot.total) - snapshot.enabled.len(),
        "slot_status": slots,
    })
}

fn snapshot_value(snapshot: Option<&LuksSnapshot>) -> Value {
    snapshot
        .map(slot_summary)
        .unwrap_or_else(|| json!({ "total": 0, "used": 0, "available": 0, "slot_status": [] }))
}

fn key_presence(paths: &Paths, service: &str) -> std::result::Result<bool, &'static str> {
    let path = paths.fixed(&format!("vault/.keys/{service}.key"));
    let mut parent = paths.root.clone();
    for component in ["vault", ".keys"] {
        parent.push(component);
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err("keyman-key-presence-observation-failed");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err("keyman-key-presence-observation-failed"),
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err("keyman-key-presence-observation-failed")
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("keyman-key-presence-observation-failed"),
    }
}

fn cryptsetup_backing(paths: &Paths, mapper: &Device) -> std::result::Result<Device, &'static str> {
    let mut command = Command::new("cryptsetup");
    command.arg("status").arg(&mapper.command_path);
    let output = command_output(&mut command, "keyman-mapper-observation-failed")?;
    if !output.status.success() {
        return Err("keyman-mapper-observation-failed");
    }
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| "keyman-mapper-observation-failed")?;
    let mut devices = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("device:").map(str::trim));
    let backing = devices
        .next()
        .filter(|value| !value.is_empty())
        .ok_or("keyman-mapper-backing-missing")?;
    if devices.next().is_some() {
        return Err("keyman-mapper-backing-ambiguous");
    }
    reported_device(paths, backing)
}

fn mapper_device(paths: &Paths, name: &str) -> std::result::Result<Device, &'static str> {
    device_node(paths, &format!("/dev/mapper/{name}"))
}

#[derive(Debug)]
enum MountState {
    Absent,
    Mounted(Device),
}

fn find_exact_mount(paths: &Paths, role: &str) -> std::result::Result<MountState, &'static str> {
    let relative = match role {
        "nas" => "mnt/nas",
        "nas_backup" => "mnt/nas_backup",
        _ => return Err("keyman-mount-role-invalid"),
    };
    let path = paths.fixed(relative);
    let mut command = Command::new("findmnt");
    command.args(["--noheadings", "--output", "SOURCE", "--mountpoint"]);
    command.arg(&path);
    let output = command_output(&mut command, "keyman-mount-observation-failed")?;
    if !output.status.success() {
        if output.status.code() == Some(1) {
            return Ok(MountState::Absent);
        }
        return Err("keyman-mount-observation-failed");
    }
    let source = std::str::from_utf8(&output.stdout)
        .map_err(|_| "keyman-mount-source-invalid")?
        .trim();
    if source.is_empty() {
        return Err("keyman-mount-source-missing");
    }
    let source = reported_device(paths, source).map_err(|_| "keyman-mount-source-invalid")?;
    Ok(MountState::Mounted(source))
}

#[derive(Clone, Debug)]
struct MountedExternal {
    role: &'static str,
    mount_source: Device,
    backing: Device,
}

fn external_mounts(paths: &Paths) -> (Vec<MountedExternal>, Vec<Value>, Option<&'static str>) {
    let mut devices = Vec::new();
    let mut observations = Vec::new();
    let mut first_signal = None;
    for role in ["nas", "nas_backup"] {
        match find_exact_mount(paths, role) {
            Ok(MountState::Absent) => observations.push(json!({ "role": role, "mounted": false })),
            Ok(MountState::Mounted(source)) => match cryptsetup_backing(paths, &source) {
                Ok(backing) => {
                    observations.push(json!({
                        "role": role,
                        "mounted": true,
                        "device": backing.logical,
                    }));
                    devices.push(MountedExternal {
                        role: if role == "nas" { "nas" } else { "nas_backup" },
                        mount_source: source,
                        backing,
                    });
                }
                Err(signal) => {
                    first_signal.get_or_insert(signal);
                    observations.push(json!({
                        "role": role,
                        "mounted": true,
                        "device": source.logical,
                        "ok": false,
                        "signal": signal,
                    }));
                }
            },
            Err(signal) => {
                first_signal.get_or_insert(signal);
                observations
                    .push(json!({ "role": role, "mounted": null, "ok": false, "signal": signal }));
            }
        }
    }
    (devices, observations, first_signal)
}

fn key_status(args: &[String]) -> Value {
    let explicit = match parse_status_args(args) {
        Ok(value) => value,
        Err(signal) => return failure_receipt("key-status", false, false, signal, json!({})),
    };
    let paths = match paths() {
        Ok(paths) => paths,
        Err(signal) => return failure_receipt("key-status", false, false, signal, json!({})),
    };
    let nas_present = match key_presence(&paths, "nas") {
        Ok(value) => value,
        Err(signal) => return failure_receipt("key-status", false, false, signal, json!({})),
    };
    let suite_present = match key_presence(&paths, "service_suite") {
        Ok(value) => value,
        Err(signal) => return failure_receipt("key-status", false, false, signal, json!({})),
    };
    let mut rows = Vec::new();
    let mut observations = Vec::new();
    let mut first_signal = None;
    if let Some(explicit) = explicit {
        match device_node(&paths, &explicit) {
            Ok(device) => match status_row(&device, "explicit") {
                Ok(row) => rows.push(row),
                Err(signal) => {
                    first_signal = Some(signal);
                    rows.push(json!({
                        "device": device.logical,
                        "role": "explicit",
                        "is_luks": null,
                        "slots": null,
                        "ok": false,
                        "signal": signal,
                    }));
                }
            },
            Err(signal) => {
                first_signal = Some(signal);
                rows.push(json!({
                    "device": explicit,
                    "role": "explicit",
                    "is_luks": null,
                    "slots": null,
                    "ok": false,
                    "signal": signal,
                }));
            }
        }
    } else {
        match mapper_device(&paths, "vault").and_then(|mapper| cryptsetup_backing(&paths, &mapper))
        {
            Ok(backing) => match status_row(&backing, "vault") {
                Ok(row) => rows.push(row),
                Err(signal) => {
                    first_signal = Some(signal);
                    rows.push(json!({
                        "device": backing.logical,
                        "role": "vault",
                        "is_luks": null,
                        "slots": null,
                        "ok": false,
                        "signal": signal,
                    }));
                }
            },
            Err(signal) => {
                first_signal = Some(signal);
                rows.push(json!({
                    "device": "/dev/mapper/vault",
                    "role": "vault",
                    "is_luks": null,
                    "slots": null,
                    "ok": false,
                    "signal": signal,
                }));
            }
        }
        let (external, observed, signal) = external_mounts(&paths);
        observations = observed;
        if first_signal.is_none() {
            first_signal = signal;
        }
        for device in external {
            match status_row(&device.backing, device.role) {
                Ok(row) => rows.push(row),
                Err(signal) => {
                    first_signal.get_or_insert(signal);
                    rows.push(json!({
                        "device": device.backing.logical,
                        "role": device.role,
                        "is_luks": null,
                        "slots": null,
                        "ok": false,
                        "signal": signal,
                    }));
                }
            }
        }
        for observation in &observations {
            if observation.get("mounted").and_then(Value::as_bool) == Some(true)
                && observation.get("ok").and_then(Value::as_bool) == Some(false)
            {
                rows.push(json!({
                    "device": observation.get("device").cloned().unwrap_or(Value::Null),
                    "role": observation.get("role").cloned().unwrap_or(Value::Null),
                    "is_luks": null,
                    "slots": null,
                    "ok": false,
                    "signal": observation.get("signal").cloned().unwrap_or(Value::Null),
                }));
            }
        }
    }
    let details = json!({
        "rows": rows,
        "observations": observations,
        "nas_key_present": nas_present,
        "service_suite_key_present": suite_present,
    });
    match first_signal {
        Some(signal) => failure_receipt("key-status", false, false, signal, details),
        None => success_receipt("key-status", false, false, details),
    }
}

fn status_row(device: &Device, role: &str) -> std::result::Result<Value, &'static str> {
    let snapshot = inspect_luks(device)?;
    Ok(json!({
        "device": device.logical,
        "role": role,
        "is_luks": snapshot.is_some(),
        "slots": snapshot_value(snapshot.as_ref()),
    }))
}

fn nas_key_password(paths: &Paths) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
    let plaintext = decrypt_service_key(paths, "nas").map_err(|_| "keyman-nas-key-unavailable")?;
    let password =
        extract_quoted_field(&plaintext, b"password=").map_err(|_| "keyman-nas-key-invalid")?;
    if password.is_empty() {
        return Err("keyman-nas-key-invalid");
    }
    Ok(password)
}

#[derive(Clone, Debug)]
struct SlotAction {
    operation: &'static str,
    slot: u8,
    authorization: &'static str,
}

fn action_value(action: &SlotAction) -> Value {
    json!({ "action": action.operation, "slot": action.slot })
}

fn make_slot_plan(
    snapshot: &LuksSnapshot,
    strategy: Strategy,
    vault: bool,
) -> std::result::Result<Vec<SlotAction>, &'static str> {
    let mut actions = Vec::new();
    match strategy {
        Strategy::SafeRotation => {
            let slot = if snapshot.enabled.contains(&1) { 2 } else { 1 };
            if slot >= snapshot.total {
                return Err("keyman-device-slots-full");
            }
            actions.push(SlotAction {
                operation: if snapshot.enabled.contains(&slot) {
                    "replace"
                } else {
                    "add"
                },
                slot,
                authorization: "current",
            });
        }
        Strategy::ReplacePrimary => {
            if snapshot.total == 0 {
                return Err("keyman-device-not-luks");
            }
            actions.push(SlotAction {
                operation: if snapshot.enabled.contains(&0) {
                    "replace"
                } else {
                    "add"
                },
                slot: 0,
                authorization: "current",
            });
            for slot in snapshot.enabled.iter().copied() {
                if slot != 0 && slot != 1 {
                    actions.push(SlotAction {
                        operation: "remove",
                        slot,
                        authorization: "new",
                    });
                }
            }
        }
        Strategy::FlexibleAddition => {
            let slot = (0..snapshot.total)
                .find(|slot| !snapshot.enabled.contains(slot) && !(vault && *slot == 1))
                .ok_or("keyman-device-slots-full")?;
            actions.push(SlotAction {
                operation: "add",
                slot,
                authorization: "current",
            });
        }
    }
    Ok(actions)
}

fn add_or_change_key(
    device: &Device,
    slot: u8,
    current: &[u8],
    current_file: Option<&Path>,
    current_slots: &[u8],
    new: &[u8],
    replace: bool,
    changed: &mut bool,
) -> std::result::Result<bool, &'static str> {
    if replace && slot == 1 {
        return Err("keyman-vault-birth-slot-protected");
    }
    if replace && !test_auth_passphrase(device, current, current_file, Some(slot))? {
        let mut has_surviving_auth = false;
        for candidate in current_slots
            .iter()
            .copied()
            .filter(|candidate| *candidate != slot)
        {
            if test_auth_passphrase(device, current, current_file, Some(candidate))? {
                has_surviving_auth = true;
                break;
            }
        }
        if !has_surviving_auth {
            return Err("keyman-device-current-key-not-surviving");
        }
        if !kill_slot(device, slot, current, current_file)? {
            return Ok(false);
        }
        *changed = true;
        return issue_key_add(device, slot, current, current_file, new, changed);
    }
    issue_key_change(device, slot, current, current_file, new, replace, changed)
}

fn issue_key_change(
    device: &Device,
    slot: u8,
    current: &[u8],
    current_file: Option<&Path>,
    new: &[u8],
    replace: bool,
    changed: &mut bool,
) -> std::result::Result<bool, &'static str> {
    let key = SecretMemfd::new(new).map_err(|_| "keyman-device-key-material-failed")?;
    let inherited_fd = key.raw_fd();
    let mut command = Command::new("cryptsetup");
    if replace {
        command.args(["luksChangeKey", "--key-slot"]);
    } else {
        command.args(["luksAddKey", "--key-slot"]);
    }
    command.arg(slot.to_string());
    match current_file {
        Some(path) => {
            command.args(["--key-file"]).arg(path);
        }
        None => {
            command.args(["--key-file", "-"]);
        }
    }
    command.arg(&device.path).arg("/proc/self/fd/3");
    unsafe {
        command.pre_exec(move || {
            if inherited_fd != 3 && libc::dup2(inherited_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .stdin(if current_file.is_some() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "keyman-device-key-write-failed")?;
    if current_file.is_none() {
        feed_secret(&mut child, current, "keyman-device-key-write-failed")?;
    }
    let status = child.wait().map_err(|_| "keyman-device-key-write-failed")?;
    if status.success() {
        *changed = true;
    }
    Ok(status.success())
}

fn issue_key_add(
    device: &Device,
    slot: u8,
    current: &[u8],
    current_file: Option<&Path>,
    new: &[u8],
    changed: &mut bool,
) -> std::result::Result<bool, &'static str> {
    issue_key_change(device, slot, current, current_file, new, false, changed)
}

fn kill_slot(
    device: &Device,
    slot: u8,
    authorization: &[u8],
    authorization_file: Option<&Path>,
) -> std::result::Result<bool, &'static str> {
    if slot == 1 {
        return Err("keyman-vault-birth-slot-protected");
    }
    let mut command = Command::new("cryptsetup");
    command.args(["luksKillSlot"]);
    match authorization_file {
        Some(path) => {
            command.args(["--key-file"]).arg(path);
        }
        None => {
            command.args(["--key-file", "-"]);
        }
    }
    command.arg(&device.path).arg(slot.to_string());
    if authorization_file.is_some() {
        let output = command_output(&mut command, "keyman-device-key-remove-failed")?;
        Ok(output.status.success())
    } else {
        secret_command(
            &mut command,
            authorization,
            "keyman-device-key-remove-failed",
        )
    }
}

fn accepted_slots(
    device: &Device,
    snapshot: &LuksSnapshot,
    password: &[u8],
    key_file: Option<&Path>,
) -> std::result::Result<Vec<u8>, &'static str> {
    let mut accepted = Vec::new();
    for slot in snapshot.enabled.iter().copied() {
        if test_auth_passphrase(device, password, key_file, Some(slot))? {
            accepted.push(slot);
        }
    }
    Ok(accepted)
}

struct DeviceOutcome {
    value: Value,
    changed: bool,
    signal: Option<&'static str>,
}

fn failed_device_outcome(
    device: &Device,
    role: &str,
    signal: &'static str,
    changed: bool,
    before: Option<&LuksSnapshot>,
    plan: &[SlotAction],
    after: Option<&LuksSnapshot>,
    current_slots: &[u8],
    new_slots: &[u8],
) -> DeviceOutcome {
    DeviceOutcome {
        value: json!({
            "device": device.logical,
            "role": role,
            "ok": false,
            "changed": changed,
            "slots_before": before.map(slot_summary),
            "plan": plan.iter().map(action_value).collect::<Vec<_>>(),
            "slots_after": after.map(slot_summary),
            "accepted_current_slots": current_slots,
            "accepted_new_slots_before": new_slots,
            "signal": signal,
        }),
        changed,
        signal: Some(signal),
    }
}

fn plan_and_apply_device(
    device: &Device,
    role: &str,
    strategy: Strategy,
    current: &[u8],
    new: &[u8],
    birth: Option<&[u8]>,
    current_file: Option<&Path>,
    birth_file: Option<&Path>,
    vault: bool,
    planned: bool,
    invalid_signal: &'static str,
) -> DeviceOutcome {
    let snapshot = match inspect_luks(device) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return failed_device_outcome(
                device,
                role,
                "keyman-device-not-luks",
                false,
                None,
                &[],
                None,
                &[],
                &[],
            )
        }
        Err(signal) => {
            return failed_device_outcome(device, role, signal, false, None, &[], None, &[], &[])
        }
    };
    let current_slots = match accepted_slots(device, &snapshot, current, current_file) {
        Ok(slots) => slots,
        Err(signal) => {
            return failed_device_outcome(
                device,
                role,
                signal,
                false,
                Some(&snapshot),
                &[],
                None,
                &[],
                &[],
            )
        }
    };
    if current_slots.is_empty() {
        return failed_device_outcome(
            device,
            role,
            invalid_signal,
            false,
            Some(&snapshot),
            &[],
            None,
            &[],
            &[],
        );
    }
    if vault {
        let Some(_birth) = birth else {
            return failed_device_outcome(
                device,
                role,
                "keyman-vault-birth-key-unavailable",
                false,
                Some(&snapshot),
                &[],
                None,
                &current_slots,
                &[],
            );
        };
        let Some(birth_file) = birth_file else {
            return failed_device_outcome(
                device,
                role,
                "keyman-vault-birth-key-unavailable",
                false,
                Some(&snapshot),
                &[],
                None,
                &current_slots,
                &[],
            );
        };
        match test_passphrase_file(device, birth_file, Some(1)) {
            Ok(true) if snapshot.enabled.contains(&1) => {}
            Ok(_) => {
                return failed_device_outcome(
                    device,
                    role,
                    "keyman-vault-birth-key-invalid",
                    false,
                    Some(&snapshot),
                    &[],
                    None,
                    &current_slots,
                    &[],
                )
            }
            Err(signal) => {
                return failed_device_outcome(
                    device,
                    role,
                    signal,
                    false,
                    Some(&snapshot),
                    &[],
                    None,
                    &current_slots,
                    &[],
                )
            }
        }
    }
    let new_slots = match accepted_slots(device, &snapshot, new, None) {
        Ok(slots) => slots,
        Err(signal) => {
            return failed_device_outcome(
                device,
                role,
                signal,
                false,
                Some(&snapshot),
                &[],
                None,
                &current_slots,
                &[],
            )
        }
    };
    let plan = match make_slot_plan(&snapshot, strategy, vault) {
        Ok(plan) => plan,
        Err(signal) => {
            return failed_device_outcome(
                device,
                role,
                signal,
                false,
                Some(&snapshot),
                &[],
                None,
                &current_slots,
                &new_slots,
            )
        }
    };
    if planned {
        return DeviceOutcome {
            value: json!({
                "device": device.logical,
                "role": role,
                "ok": true,
                "changed": false,
                "slots_before": slot_summary(&snapshot),
                "plan": plan.iter().map(action_value).collect::<Vec<_>>(),
                "slots_after": slot_summary(&snapshot),
                "accepted_current_slots": current_slots,
                "accepted_new_slots_before": new_slots,
            }),
            changed: false,
            signal: None,
        };
    }
    let mut changed = false;
    for action in &plan {
        let use_new = action.authorization == "new";
        let authorization = if use_new { new } else { current };
        let authorization_file = if use_new { None } else { current_file };
        let result = match action.operation {
            "add" => add_or_change_key(
                device,
                action.slot,
                authorization,
                authorization_file,
                &current_slots,
                new,
                false,
                &mut changed,
            ),
            "replace" => add_or_change_key(
                device,
                action.slot,
                authorization,
                authorization_file,
                &current_slots,
                new,
                true,
                &mut changed,
            ),
            "remove" => {
                let removed = kill_slot(device, action.slot, authorization, authorization_file);
                if matches!(removed, Ok(true)) {
                    changed = true;
                }
                removed
            }
            _ => Err("keyman-slot-plan-invalid"),
        };
        match result {
            Ok(true) => {
                if matches!(action.operation, "add" | "replace") {
                    match test_passphrase(device, new, Some(action.slot)) {
                        Ok(true) => {}
                        Ok(false) => {
                            let after = inspect_luks(device).ok().flatten();
                            return failed_device_outcome(
                                device,
                                role,
                                "keyman-device-new-password-unverified",
                                changed,
                                Some(&snapshot),
                                &plan,
                                after.as_ref(),
                                &current_slots,
                                &new_slots,
                            );
                        }
                        Err(signal) => {
                            let after = inspect_luks(device).ok().flatten();
                            return failed_device_outcome(
                                device,
                                role,
                                signal,
                                changed,
                                Some(&snapshot),
                                &plan,
                                after.as_ref(),
                                &current_slots,
                                &new_slots,
                            );
                        }
                    }
                }
            }
            Ok(false) => {
                let after = inspect_luks(device).ok().flatten();
                return failed_device_outcome(
                    device,
                    role,
                    "keyman-device-key-action-refused",
                    changed,
                    Some(&snapshot),
                    &plan,
                    after.as_ref(),
                    &current_slots,
                    &new_slots,
                );
            }
            Err(signal) => {
                let after = inspect_luks(device).ok().flatten();
                return failed_device_outcome(
                    device,
                    role,
                    signal,
                    changed,
                    Some(&snapshot),
                    &plan,
                    after.as_ref(),
                    &current_slots,
                    &new_slots,
                );
            }
        }
    }
    let after = match inspect_luks(device) {
        Ok(Some(after)) => after,
        _ => {
            return failed_device_outcome(
                device,
                role,
                "keyman-device-readback-failed",
                changed,
                Some(&snapshot),
                &plan,
                None,
                &current_slots,
                &new_slots,
            )
        }
    };
    if vault {
        let Some(birth_file) = birth_file else {
            return failed_device_outcome(
                device,
                role,
                "keyman-vault-birth-key-unavailable",
                changed,
                Some(&snapshot),
                &plan,
                Some(&after),
                &current_slots,
                &new_slots,
            );
        };
        match test_passphrase_file(device, birth_file, Some(1)) {
            Ok(true) if after.enabled.contains(&1) => {}
            Ok(_) => {
                return failed_device_outcome(
                    device,
                    role,
                    "keyman-vault-birth-key-readback-failed",
                    changed,
                    Some(&snapshot),
                    &plan,
                    Some(&after),
                    &current_slots,
                    &new_slots,
                )
            }
            Err(signal) => {
                return failed_device_outcome(
                    device,
                    role,
                    signal,
                    changed,
                    Some(&snapshot),
                    &plan,
                    Some(&after),
                    &current_slots,
                    &new_slots,
                )
            }
        }
    }
    let final_new_slots = match accepted_slots(device, &after, new, None) {
        Ok(slots) => slots,
        Err(signal) => {
            return failed_device_outcome(
                device,
                role,
                signal,
                changed,
                Some(&snapshot),
                &plan,
                Some(&after),
                &current_slots,
                &new_slots,
            )
        }
    };
    match final_new_slots {
        slots if !slots.is_empty() => DeviceOutcome {
            value: json!({
                "device": device.logical,
                "role": role,
                "ok": true,
                "changed": changed,
                "slots_before": slot_summary(&snapshot),
                "plan": plan.iter().map(action_value).collect::<Vec<_>>(),
                "slots_after": slot_summary(&after),
                "accepted_current_slots": current_slots,
                "accepted_new_slots_before": new_slots,
                "accepted_new_slots_after": slots,
            }),
            changed,
            signal: None,
        },
        _ => failed_device_outcome(
            device,
            role,
            "keyman-device-new-password-unverified",
            changed,
            Some(&snapshot),
            &plan,
            Some(&after),
            &current_slots,
            &new_slots,
        ),
    }
}

fn read_birth_key(paths: &Paths) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
    let path = paths
        .check_fixed_parent("root/key/vault-birth.key")
        .map_err(|_| "keyman-vault-birth-key-unavailable")?;
    let key = read_regular_file(&path, 64 * 1024, "cannot read vault birth key")
        .map_err(|_| "keyman-vault-birth-key-unavailable")?;
    if key.is_empty() {
        return Err("keyman-vault-birth-key-unavailable");
    }
    Ok(Zeroizing::new(key))
}

fn vault_backing(paths: &Paths) -> std::result::Result<Device, &'static str> {
    let mapper = mapper_device(paths, "vault")?;
    cryptsetup_backing(paths, &mapper)
}

fn path_same(left: &Device, right: &Device) -> bool {
    left.rdev == right.rdev
}

fn create_key(args: &[String]) -> Value {
    let document = match read_secret_document() {
        Ok(document) => document,
        Err(signal) => return failure_receipt("create-key", false, false, signal, json!({})),
    };
    let object = object(&document);
    let planned = planned_field(object).unwrap_or(false);
    if let Err(signal) = planned_field(object) {
        return failure_receipt("create-key", false, false, signal, json!({}));
    }
    let password = match secret_field(object, "password", "keyman-password-required") {
        Ok(password) => password,
        Err(signal) => return failure_receipt("create-key", planned, false, signal, json!({})),
    };
    if let Err(signal) = validate_secret(&password, "keyman-password-invalid") {
        return failure_receipt("create-key", planned, false, signal, json!({}));
    }
    let (target, strategy) = match parse_create_args(args) {
        Ok(parsed) => parsed,
        Err(signal) => return failure_receipt("create-key", planned, false, signal, json!({})),
    };
    let paths = match paths() {
        Ok(paths) => paths,
        Err(signal) => return failure_receipt("create-key", planned, false, signal, json!({})),
    };
    create_key_operation(&paths, &target, strategy, &password, planned)
}

fn create_key_operation(
    paths: &Paths,
    target: &str,
    strategy: Strategy,
    new_password: &str,
    planned: bool,
) -> Value {
    let wants_vault = matches!(target, "vault" | "both");
    let wants_external = matches!(target, "external" | "both");
    let mut details = Map::new();
    let mut outcomes = Vec::new();
    let mut changed = false;
    let mut first_signal = None;
    let previous_nas = if wants_external {
        Some(nas_key_password(paths))
    } else {
        None
    };
    let birth = if wants_vault {
        match read_birth_key(paths) {
            Ok(key) => Some(key),
            Err(signal) => {
                first_signal = Some(signal);
                None
            }
        }
    } else {
        None
    };
    let vault = if wants_vault {
        match vault_backing(paths) {
            Ok(device) => Some(device),
            Err(signal) => {
                first_signal.get_or_insert(signal);
                None
            }
        }
    } else {
        None
    };
    let birth_file = wants_vault.then(|| paths.fixed("root/key/vault-birth.key"));
    if wants_vault {
        match (vault.as_ref(), birth.as_ref()) {
            (Some(device), Some(birth)) => {
                let outcome = plan_and_apply_device(
                    device,
                    "vault",
                    strategy,
                    birth.as_slice(),
                    new_password.as_bytes(),
                    Some(birth.as_slice()),
                    birth_file.as_deref(),
                    birth_file.as_deref(),
                    true,
                    planned,
                    "keyman-vault-birth-key-invalid",
                );
                changed |= outcome.changed;
                if let Some(signal) = outcome.signal {
                    first_signal.get_or_insert(signal);
                }
                outcomes.push(outcome.value);
            }
            _ => outcomes.push(json!({
                "device": "/dev/mapper/vault",
                "role": "vault",
                "ok": false,
                "changed": false,
                "signal": first_signal.unwrap_or("keyman-vault-observation-failed"),
            })),
        }
    }
    let mut nas_key_rewritten = false;
    let mut nas_key_rewrite_planned = false;
    if wants_external {
        let (mounted, observations, observation_signal) = external_mounts(paths);
        details.insert("external_mounts".into(), Value::Array(observations.clone()));
        if let Some(signal) = observation_signal {
            first_signal.get_or_insert(signal);
        }
        let vault_for_skip = vault
            .as_ref()
            .cloned()
            .or_else(|| vault_backing(paths).ok());
        let vault_target = vault_for_skip.as_ref();
        let mut seen_devices = BTreeSet::new();
        let eligible: Vec<&MountedExternal> = mounted
            .iter()
            .filter(|item| {
                !vault_target.is_some_and(|device| path_same(device, &item.backing))
                    && item.mount_source.logical != "/dev/mapper/vault"
            })
            .filter(|item| seen_devices.insert(item.backing.rdev))
            .collect();
        for observation in &observations {
            if observation.get("ok").and_then(Value::as_bool) == Some(false) {
                outcomes.push(json!({
                    "device": observation.get("device").cloned().unwrap_or(Value::Null),
                    "role": observation.get("role").cloned().unwrap_or(Value::Null),
                    "ok": false,
                    "changed": false,
                    "signal": observation.get("signal").cloned().unwrap_or(Value::Null),
                }));
            }
        }
        let previous = previous_nas
            .as_ref()
            .expect("external target pre-reads NAS credential")
            .as_ref()
            .map_err(|signal| *signal);
        if eligible.is_empty() {
            first_signal.get_or_insert("keyman-external-device-not-mounted");
            details.insert("external_devices".into(), json!([]));
        } else if let Err(signal) = &previous {
            first_signal.get_or_insert(*signal);
            for item in &eligible {
                outcomes.push(json!({
                    "device": item.backing.logical,
                    "role": item.role,
                    "ok": false,
                    "changed": false,
                    "signal": signal,
                }));
            }
        } else {
            let previous = previous.expect("checked successful previous NAS credential");
            details.insert(
                "external_devices".into(),
                Value::Array(
                    eligible
                        .iter()
                        .map(|item| json!({ "device": item.backing.logical, "role": item.role }))
                        .collect(),
                ),
            );
            if planned {
                nas_key_rewrite_planned = true;
                for item in &eligible {
                    let outcome = plan_and_apply_device(
                        &item.backing,
                        item.role,
                        strategy,
                        previous.as_slice(),
                        new_password.as_bytes(),
                        None,
                        None,
                        None,
                        false,
                        true,
                        "keyman-nas-key-invalid",
                    );
                    if let Some(signal) = outcome.signal {
                        first_signal.get_or_insert(signal);
                    }
                    outcomes.push(outcome.value);
                }
            } else {
                match native_newkey(paths, "nas", "admin", new_password) {
                    Ok(_) => {
                        nas_key_rewritten = true;
                        changed = true;
                        match export_nas_password(paths) {
                            Ok(exported) => {
                                for item in &eligible {
                                    let outcome = plan_and_apply_device(
                                        &item.backing,
                                        item.role,
                                        strategy,
                                        previous.as_slice(),
                                        &exported,
                                        None,
                                        None,
                                        None,
                                        false,
                                        false,
                                        "keyman-nas-key-invalid",
                                    );
                                    changed |= outcome.changed;
                                    if let Some(signal) = outcome.signal {
                                        first_signal.get_or_insert(signal);
                                    }
                                    outcomes.push(outcome.value);
                                }
                            }
                            Err(signal) => {
                                first_signal.get_or_insert(signal);
                                for item in &eligible {
                                    outcomes.push(json!({
                                        "device": item.backing.logical,
                                        "role": item.role,
                                        "ok": false,
                                        "changed": false,
                                        "signal": signal,
                                    }));
                                }
                            }
                        }
                    }
                    Err(_) => {
                        first_signal.get_or_insert("keyman-nas-key-write-failed");
                        for item in &eligible {
                            outcomes.push(json!({
                                "device": item.backing.logical,
                                "role": item.role,
                                "ok": false,
                                "changed": false,
                                "signal": "keyman-nas-key-write-failed",
                            }));
                        }
                    }
                }
            }
        }
        let device_failed = outcomes
            .iter()
            .any(|outcome| outcome.get("ok").and_then(Value::as_bool) == Some(false));
        details.insert("nas_key_rewritten".into(), Value::Bool(nas_key_rewritten));
        details.insert(
            "nas_key_rewrite_planned".into(),
            Value::Bool(nas_key_rewrite_planned),
        );
        if nas_key_rewritten {
            details.insert("partial_success".into(), Value::Bool(device_failed));
        }
    }
    details.insert("target".into(), Value::String(target.to_owned()));
    details.insert("strategy".into(), Value::String(strategy.name().to_owned()));
    details.insert("devices".into(), Value::Array(outcomes));
    match first_signal {
        Some(signal) => failure_receipt(
            "create-key",
            planned,
            changed,
            signal,
            Value::Object(details),
        ),
        None => success_receipt("create-key", planned, changed, Value::Object(details)),
    }
}

fn exchange_lock(paths: &Paths) -> std::result::Result<File, &'static str> {
    let path = paths
        .check_fixed_parent("root/key/skeleton.key")
        .map_err(|_| "keyman-exchange-lock-unavailable")?;
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| "keyman-exchange-lock-unavailable")?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err("keyman-exchange-lock-failed");
    }
    Ok(file)
}

pub(crate) struct ExchangeSession {
    directory: PathBuf,
    mounted: bool,
    export_identity: Option<(PathBuf, u64, u64)>,
    finished: bool,
}

impl ExchangeSession {
    pub(crate) fn begin(paths: &Paths) -> std::result::Result<Self, &'static str> {
        paths
            .ensure_directories("mnt")
            .map_err(|_| "keyman-exchange-directory-failed")?;
        let directory = paths.fixed("mnt/keyexchange");
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("keyman-exchange-must-be-absent-at-rest"),
        }
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&directory)
            .map_err(|_| "keyman-exchange-directory-failed")?;
        let source =
            CString::new("keyman-crown-exchange").map_err(|_| "keyman-exchange-mount-failed")?;
        let target = CString::new(directory.as_os_str().as_encoded_bytes())
            .map_err(|_| "keyman-exchange-mount-failed")?;
        let fs_type = CString::new("tmpfs").map_err(|_| "keyman-exchange-mount-failed")?;
        let data = CString::new("size=1m,mode=0700").map_err(|_| "keyman-exchange-mount-failed")?;
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fs_type.as_ptr(),
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
                data.as_ptr().cast(),
            )
        };
        if result != 0 {
            let _ = fs::remove_dir(&directory);
            return Err("keyman-exchange-mount-failed");
        }
        Ok(Self {
            directory,
            mounted: true,
            export_identity: None,
            finished: false,
        })
    }

    fn export(
        &mut self,
        paths: &Paths,
        service: &str,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
        let (path, device, inode) = native_export_to_directory(paths, service, &self.directory)
            .map_err(|_| "keyman-exchange-export-failed")?;
        self.export_identity = Some((path.clone(), device, inode));
        let bytes = read_regular_file(&path, MAX_KEY_FILE, "cannot read exchange key")
            .map_err(|_| "keyman-exchange-read-failed")?;
        Ok(Zeroizing::new(bytes))
    }

    pub(crate) fn cleanup(&mut self) -> std::result::Result<(), &'static str> {
        let mut first_error = None;
        if let Some((path, device, inode)) = self.export_identity.take() {
            match secure_remove_if_identity(&path, device, inode) {
                Ok(true) => {}
                Ok(false) => {
                    if path.exists() {
                        first_error = Some("keyman-exchange-file-cleanup-failed");
                    }
                }
                Err(_) => first_error = Some("keyman-exchange-file-cleanup-failed"),
            }
        }
        if self.mounted {
            let target = match CString::new(self.directory.as_os_str().as_encoded_bytes()) {
                Ok(target) => target,
                Err(_) => {
                    self.finished = true;
                    return Err(first_error.unwrap_or("keyman-exchange-unmount-failed"));
                }
            };
            let unmounted = unsafe { libc::umount2(target.as_ptr(), 0) } == 0;
            if unmounted {
                self.mounted = false;
            } else {
                first_error.get_or_insert("keyman-exchange-unmount-failed");
                if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } == 0 {
                    self.mounted = false;
                }
            }
        }
        if !self.mounted {
            if fs::remove_dir(&self.directory).is_err() {
                first_error.get_or_insert("keyman-exchange-directory-cleanup-failed");
            }
        }
        self.finished = true;
        match first_error {
            Some(signal) => Err(signal),
            None => Ok(()),
        }
    }
}

impl Drop for ExchangeSession {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cleanup();
        }
    }
}

fn export_nas_password(paths: &Paths) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
    let lock = exchange_lock(paths)?;
    let mut session = ExchangeSession::begin(paths)?;
    let result = session.export(paths, "nas").and_then(|document| {
        extract_quoted_field(&document, b"password=").map_err(|_| "keyman-exchange-export-invalid")
    });
    let cleanup = session.cleanup();
    drop(session);
    drop(lock);
    match (result, cleanup) {
        (Ok(password), Ok(())) if !password.is_empty() => Ok(password),
        (Ok(_), Ok(())) => Err("keyman-exchange-export-invalid"),
        (Err(signal), Ok(())) => Err(signal),
        (_, Err(signal)) => Err(signal),
    }
}

fn update_key(args: &[String]) -> Value {
    let document = match read_secret_document() {
        Ok(document) => document,
        Err(signal) => return failure_receipt("update-key", false, false, signal, json!({})),
    };
    let object = object(&document);
    let planned = planned_field(object).unwrap_or(false);
    if let Err(signal) = planned_field(object) {
        return failure_receipt("update-key", false, false, signal, json!({}));
    }

    let current = match secret_field(
        object,
        "current_password",
        "keyman-current-password-required",
    ) {
        Ok(current) => current,
        Err(signal) => return failure_receipt("update-key", planned, false, signal, json!({})),
    };
    if let Err(signal) = validate_secret(&current, "keyman-current-password-invalid") {
        return failure_receipt("update-key", planned, false, signal, json!({}));
    }
    let parsed = match parse_update_args(args) {
        Ok(parsed) => parsed,
        Err(signal) => return failure_receipt("update-key", planned, false, signal, json!({})),
    };
    let paths = match paths() {
        Ok(paths) => paths,
        Err(signal) => return failure_receipt("update-key", planned, false, signal, json!({})),
    };
    update_key_operation(&paths, &parsed.0, parsed.1, &current, planned)
}

fn update_key_operation(
    paths: &Paths,
    device: &Device,
    strategy: Strategy,
    current: &str,
    planned: bool,
) -> Value {
    match test_passphrase(device, current.as_bytes(), None) {
        Ok(true) => {}
        Ok(false) => {
            return failure_receipt(
                "update-key",
                planned,
                false,
                "keyman-device-password-invalid",
                json!({ "device": device.logical }),
            )
        }
        Err(signal) => {
            return failure_receipt(
                "update-key",
                planned,
                false,
                signal,
                json!({ "device": device.logical }),
            )
        }
    }
    let new = match nas_key_password(paths) {
        Ok(password) => password,
        Err(signal) => {
            return failure_receipt(
                "update-key",
                planned,
                false,
                signal,
                json!({ "device": device.logical }),
            )
        }
    };
    let vault = vault_backing(paths).ok();
    let is_vault = vault.as_ref().is_some_and(|vault| path_same(vault, device));
    let birth = if is_vault {
        match read_birth_key(paths) {
            Ok(birth) => Some(birth),
            Err(signal) => {
                return failure_receipt(
                    "update-key",
                    planned,
                    false,
                    signal,
                    json!({ "device": device.logical }),
                )
            }
        }
    } else {
        None
    };
    let birth_file = is_vault.then(|| paths.fixed("root/key/vault-birth.key"));
    let outcome = plan_and_apply_device(
        device,
        if is_vault { "vault" } else { "explicit" },
        strategy,
        current.as_bytes(),
        &new,
        birth.as_ref().map(|value| value.as_slice()),
        None,
        birth_file.as_deref(),
        is_vault,
        planned,
        "keyman-device-password-invalid",
    );
    match outcome.signal {
        Some(signal) => failure_receipt(
            "update-key",
            planned,
            outcome.changed,
            signal,
            json!({ "device": outcome.value }),
        ),
        None => success_receipt(
            "update-key",
            planned,
            outcome.changed,
            json!({ "device": outcome.value }),
        ),
    }
}

struct RewrapUpdate {
    path: PathBuf,
    old: Zeroizing<Vec<u8>>,
    new: Zeroizing<Vec<u8>>,
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let limit = left.len().max(right.len());
    for index in 0..limit {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

fn valid_service_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 238
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value != "service_suite"
}

fn prepare_rewrap(
    paths: &Paths,
    current: &[u8],
    new: &[u8],
) -> std::result::Result<Vec<RewrapUpdate>, &'static str> {
    let suite_path = paths
        .check_fixed_parent("vault/.keys/service_suite.key")
        .map_err(|_| "keyman-service-suite-unavailable")?;
    let suite_encrypted = read_regular_file(&suite_path, MAX_KEY_FILE, "cannot read service suite")
        .map_err(|_| "keyman-service-suite-unavailable")?;
    let skeleton = paths
        .read_skeleton()
        .map_err(|_| "keyman-service-suite-unavailable")?;
    let suite_plain =
        decrypt_blob(&skeleton, &suite_encrypted).map_err(|_| "keyman-service-suite-invalid")?;
    let stored = extract_quoted_field(&suite_plain, b"password=")
        .map_err(|_| "keyman-service-suite-invalid")?;
    if !constant_time_equal(&stored, current) {
        return Err("keyman-admin-password-invalid");
    }
    let vault_dir = paths.fixed("vault/.keys");
    let directory_metadata =
        fs::symlink_metadata(&vault_dir).map_err(|_| "keyman-service-key-directory-unavailable")?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err("keyman-service-key-directory-unavailable");
    }
    let entries =
        fs::read_dir(&vault_dir).map_err(|_| "keyman-service-key-directory-unavailable")?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| "keyman-service-key-directory-unavailable")?;
        let Some(filename) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(service) = filename.strip_suffix(".key") else {
            continue;
        };
        if service == "service_suite" {
            continue;
        }
        if !valid_service_name(service) {
            return Err("keyman-service-key-name-invalid");
        }
        let file_type = entry
            .file_type()
            .map_err(|_| "keyman-service-key-observation-failed")?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err("keyman-service-key-observation-failed");
        }
        names.push(service.to_owned());
    }
    names.sort();
    let mut updates = Vec::with_capacity(names.len() + 1);
    for service in names {
        let relative = format!("vault/.keys/{service}.key");
        let path = paths
            .check_fixed_parent(&relative)
            .map_err(|_| "keyman-service-key-observation-failed")?;
        let old = read_regular_file(&path, MAX_KEY_FILE, "cannot read service key")
            .map_err(|_| "keyman-service-key-observation-failed")?;
        let plaintext = decrypt_blob(current, &old).map_err(|_| "keyman-service-key-invalid")?;
        let encrypted =
            encrypt_blob(new, &plaintext).map_err(|_| "keyman-service-key-rewrap-failed")?;
        updates.push(RewrapUpdate {
            path,
            old: Zeroizing::new(old),
            new: Zeroizing::new(encrypted),
        });
    }
    let new_suite_content = format_credentials(b"service_suite", new)
        .map_err(|_| "keyman-service-suite-rewrap-failed")?;
    let encrypted_suite = encrypt_blob(&skeleton, &new_suite_content)
        .map_err(|_| "keyman-service-suite-rewrap-failed")?;
    updates.push(RewrapUpdate {
        path: suite_path,
        old: Zeroizing::new(suite_encrypted),
        new: Zeroizing::new(encrypted_suite),
    });
    Ok(updates)
}

fn restore_updates(updates: &[RewrapUpdate], count: usize) -> bool {
    let mut restored = true;
    for update in updates.iter().take(count).rev() {
        if write_atomic(&update.path, &update.old).is_err() {
            restored = false;
        }
    }
    restored
}

fn commit_rewrap(updates: &[RewrapUpdate]) -> std::result::Result<(), (usize, &'static str)> {
    for (index, update) in updates.iter().enumerate() {
        if write_atomic(&update.path, &update.new).is_err() {
            return Err((index, "keyman-service-key-rewrap-failed"));
        }
    }
    Ok(())
}

fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

fn run_chpasswd(paths: &Paths, password: &str) -> bool {
    let Some(program) = find_executable("chpasswd") else {
        return false;
    };
    let mut command = Command::new(program);
    if paths.rooted {
        command
            .args(["--prefix"])
            .arg(&paths.root)
            .args(["--crypt-method", "SHA512"]);
    }
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() + 7));
    input.extend_from_slice(b"owner:");
    input.extend_from_slice(password.as_bytes());
    input.push(b'\n');
    secret_command(&mut command, &input, "keyman-owner-password-command-failed").unwrap_or(false)
}

fn rooted_samba_config(paths: &Paths) -> std::result::Result<PathBuf, &'static str> {
    let path = paths.root.join("etc/samba/smb.conf");
    let relative = Path::new("etc/samba/smb.conf");
    let mut current = paths.root.clone();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err("keyman-samba-rooted-config-missing");
        };
        current.push(name);
        if current == path {
            break;
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| "keyman-samba-rooted-config-missing")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("keyman-samba-rooted-config-missing");
        }
    }
    let metadata = fs::symlink_metadata(&path).map_err(|_| "keyman-samba-rooted-config-missing")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("keyman-samba-rooted-config-missing");
    }
    Ok(path)
}

fn run_smbpasswd(paths: &Paths, password: &str) -> std::result::Result<Option<bool>, &'static str> {
    let Some(program) = find_executable("smbpasswd") else {
        return Ok(None);
    };
    let mut command = Command::new(program);
    if paths.rooted {
        command.arg("-c").arg(rooted_samba_config(paths)?);
    }
    command.args(["-s", "owner"]);
    let mut input = Zeroizing::new(Vec::with_capacity(password.len() * 2 + 2));
    input.extend_from_slice(password.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(password.as_bytes());
    input.push(b'\n');
    let ok = secret_command(&mut command, &input, "keyman-samba-password-command-failed")
        .unwrap_or(false);
    Ok(Some(ok))
}

fn unit_exists(paths: &Paths, unit: &str) -> bool {
    [
        format!("etc/systemd/system/{unit}"),
        format!("lib/systemd/system/{unit}"),
        format!("usr/lib/systemd/system/{unit}"),
    ]
    .iter()
    .any(|relative| {
        let path = paths.fixed(relative);
        fs::symlink_metadata(path)
            .is_ok_and(|metadata| metadata.is_file() || metadata.file_type().is_symlink())
    })
}

fn restart_units(paths: &Paths) -> Value {
    if paths.rooted {
        return json!({
            "ssh.service": { "status": "skipped_rooted_isolation", "attempted": false },
            "sshd.service": { "status": "skipped_rooted_isolation", "attempted": false },
            "smbd.service": { "status": "skipped_rooted_isolation", "attempted": false },
        });
    }
    let mut statuses = Map::new();
    for unit in ["ssh.service", "sshd.service", "smbd.service"] {
        if !unit_exists(paths, unit) {
            statuses.insert(
                unit.to_owned(),
                json!({ "status": "absent", "attempted": false }),
            );
            continue;
        }
        let mut command = Command::new("systemctl");
        command.args(["restart", unit]);
        let output = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match output {
            Ok(status) => statuses.insert(
                unit.to_owned(),
                json!({ "status": if status.success() { "restarted" } else { "failed" }, "attempted": true, "exit_code": status.code() }),
            ),
            Err(_) => statuses.insert(
                unit.to_owned(),
                json!({ "status": "failed", "attempted": true, "spawn_failed": true }),
            ),
        };
    }
    Value::Object(statuses)
}

fn admin_password(args: &[String]) -> Value {
    let document = match read_secret_document() {
        Ok(document) => document,
        Err(signal) => return failure_receipt("admin-password", false, false, signal, json!({})),
    };
    let object = object(&document);
    let planned = planned_field(object).unwrap_or(false);
    if let Err(signal) = planned_field(object) {
        return failure_receipt("admin-password", false, false, signal, json!({}));
    }

    let old = match secret_field(object, "old_password", "keyman-old-password-required") {
        Ok(value) => value,
        Err(signal) => return failure_receipt("admin-password", planned, false, signal, json!({})),
    };
    let new = match secret_field(object, "new_password", "keyman-new-password-required") {
        Ok(value) => value,
        Err(signal) => return failure_receipt("admin-password", planned, false, signal, json!({})),
    };
    if let Err(signal) = validate_secret(&old, "keyman-old-password-invalid") {
        return failure_receipt("admin-password", planned, false, signal, json!({}));
    }
    if let Err(signal) = validate_secret(&new, "keyman-new-password-invalid") {
        return failure_receipt("admin-password", planned, false, signal, json!({}));
    }
    if !args.is_empty() && args.len() != 1 {
        return failure_receipt(
            "admin-password",
            planned,
            false,
            "keyman-admin-password-usage-invalid",
            json!({}),
        );
    }
    let paths = match paths() {
        Ok(paths) => paths,
        Err(signal) => return failure_receipt("admin-password", planned, false, signal, json!({})),
    };
    admin_password_operation(&paths, &old, &new, planned)
}

fn rewrap_service_names(updates: &[RewrapUpdate]) -> Vec<String> {
    updates
        .iter()
        .filter_map(|update| {
            let name = update.path.file_name()?.to_str()?.strip_suffix(".key")?;
            (name != "service_suite").then(|| name.to_owned())
        })
        .collect()
}

fn admin_steps(
    paths: &Paths,
    services: &[String],
    service_statuses: &[&str],
    verify_status: &str,
    suite_status: &str,
    owner_status: &str,
    samba_status: &str,
    restart_statuses: Option<&Value>,
    restart_default: &str,
    rollback_status: Option<&str>,
    rollback_before_owner: bool,
) -> Vec<Value> {
    let mut steps = vec![json!({ "step": "verify-suite", "status": verify_status })];
    for (index, service) in services.iter().enumerate() {
        steps.push(json!({
            "step": "rewrap-service",
            "service": service,
            "status": service_statuses.get(index).copied().unwrap_or("not_attempted"),
        }));
    }
    steps.push(json!({ "step": "rewrite-suite", "status": suite_status }));
    if rollback_before_owner {
        if let Some(status) = rollback_status {
            steps.push(json!({ "step": "rollback", "status": status }));
        }
    }
    steps.push(json!({ "step": "owner-unix-chpasswd", "status": owner_status }));
    if !rollback_before_owner {
        if let Some(status) = rollback_status {
            steps.push(json!({ "step": "rollback", "status": status }));
        }
    }
    steps.push(json!({ "step": "samba-owner", "status": samba_status }));
    for unit in ["ssh.service", "sshd.service", "smbd.service"] {
        let observed = restart_statuses
            .and_then(|value| value.get(unit))
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str);
        let status = match observed {
            Some(status) => status,
            None if paths.rooted => "skipped_rooted_isolation",
            None if !unit_exists(paths, unit) => "absent",
            None => restart_default,
        };
        steps.push(json!({ "step": "restart-unit", "unit": unit, "status": status }));
    }
    steps
}

fn admin_password_operation(paths: &Paths, old: &str, new: &str, planned: bool) -> Value {
    let samba_available = find_executable("smbpasswd").is_some();
    if find_executable("chpasswd").is_none() {
        let steps = admin_steps(
            paths,
            &[],
            &[],
            "not_attempted",
            "not_attempted",
            "unavailable",
            if samba_available {
                "not_attempted"
            } else {
                "absent"
            },
            None,
            "not_attempted",
            None,
            false,
        );
        return failure_receipt(
            "admin-password",
            planned,
            false,
            "keyman-chpasswd-unavailable",
            json!({ "steps": steps }),
        );
    }
    let updates = match prepare_rewrap(paths, old.as_bytes(), new.as_bytes()) {
        Ok(updates) => updates,
        Err(signal) => {
            let steps = admin_steps(
                paths,
                &[],
                &[],
                "failed",
                "not_attempted",
                "not_attempted",
                if samba_available {
                    "not_attempted"
                } else {
                    "absent"
                },
                None,
                "not_attempted",
                None,
                false,
            );
            return failure_receipt(
                "admin-password",
                planned,
                false,
                signal,
                json!({ "steps": steps }),
            );
        }
    };
    let services = rewrap_service_names(&updates);
    let service_count = services.len();
    if paths.rooted && samba_available {
        if let Err(signal) = rooted_samba_config(paths) {
            let service_statuses = vec!["prepared"; service_count];
            let steps = admin_steps(
                paths,
                &services,
                &service_statuses,
                "verified",
                "prepared",
                "not_attempted",
                "refused_rooted_config_missing",
                None,
                "not_attempted",
                None,
                false,
            );
            return failure_receipt(
                "admin-password",
                planned,
                false,
                signal,
                json!({
                    "rewrapped_services": service_count,
                    "owner_password": "not_attempted",
                    "samba": "refused_rooted_config_missing",
                    "steps": steps,
                }),
            );
        }
    }
    if planned {
        let service_statuses = vec!["planned"; service_count];
        let steps = admin_steps(
            paths,
            &services,
            &service_statuses,
            "verified",
            "planned",
            "planned",
            if samba_available { "planned" } else { "absent" },
            None,
            "planned",
            None,
            false,
        );
        return success_receipt(
            "admin-password",
            true,
            false,
            json!({
                "rewrapped_services": service_count,
                "owner_password": "planned",
                "samba": if samba_available { "planned" } else { "absent" },
                "runtime_restarts": if paths.rooted { "skipped_rooted_isolation" } else { "planned" },
                "steps": steps,
            }),
        );
    }
    if let Err((written, signal)) = commit_rewrap(&updates) {
        let restored = restore_updates(&updates, written);
        let service_statuses: Vec<&str> = (0..service_count)
            .map(|index| {
                if index < written {
                    if restored {
                        "rolled_back"
                    } else {
                        "rollback_attempted"
                    }
                } else if index == written {
                    "failed"
                } else {
                    "not_attempted"
                }
            })
            .collect();
        let suite_status = if written > service_count {
            if restored {
                "rolled_back"
            } else {
                "rollback_attempted"
            }
        } else if written == service_count {
            "failed"
        } else {
            "not_attempted"
        };
        let rollback_status = if written == 0 {
            None
        } else if restored {
            Some("complete")
        } else {
            Some("incomplete")
        };
        let steps = admin_steps(
            paths,
            &services,
            &service_statuses,
            "verified",
            suite_status,
            "not_attempted",
            if samba_available {
                "not_attempted"
            } else {
                "absent"
            },
            None,
            "not_attempted",
            rollback_status,
            true,
        );
        return failure_receipt(
            "admin-password",
            false,
            !restored,
            if restored {
                signal
            } else {
                "keyman-admin-rewrap-rollback-incomplete"
            },
            json!({
                "rewrapped_services": written.min(service_count),
                "rollback_attempted": written > 0,
                "rollback_complete": restored,
                "steps": steps,
            }),
        );
    }
    if !run_chpasswd(paths, new) {
        let restored = restore_updates(&updates, updates.len());
        let status = if restored {
            "rolled_back"
        } else {
            "rollback_attempted"
        };
        let service_statuses = vec![status; service_count];
        let steps = admin_steps(
            paths,
            &services,
            &service_statuses,
            "verified",
            status,
            "failed",
            if samba_available {
                "not_attempted"
            } else {
                "absent"
            },
            None,
            "not_attempted",
            Some(if restored { "complete" } else { "incomplete" }),
            false,
        );
        return failure_receipt(
            "admin-password",
            false,
            !restored,
            if restored {
                "keyman-owner-password-update-failed"
            } else {
                "keyman-owner-password-and-rollback-failed"
            },
            json!({
                "rewrapped_services": service_count,
                "owner_password_updated": false,
                "rollback_attempted": true,
                "rollback_complete": restored,
                "samba": if samba_available { "not_attempted" } else { "absent" },
                "steps": steps,
            }),
        );
    }
    let samba = match run_smbpasswd(paths, new) {
        Ok(None) => "absent",
        Ok(Some(true)) => "updated",
        Ok(Some(false)) => "failed",
        Err("keyman-samba-rooted-config-missing") => "refused_rooted_config_missing",
        Err(_) => "failed",
    };
    let restarts = restart_units(paths);
    let service_statuses = vec!["rewrapped"; service_count];
    let steps = admin_steps(
        paths,
        &services,
        &service_statuses,
        "verified",
        "rewritten",
        "updated",
        samba,
        Some(&restarts),
        "not_attempted",
        None,
        false,
    );
    let details = json!({
        "rewrapped_services": service_count,
        "owner_password_updated": true,
        "samba": samba,
        "runtime_restarts": restarts,
        "steps": steps,
    });
    if samba == "failed" || samba == "refused_rooted_config_missing" {
        let signal = if samba == "refused_rooted_config_missing" {
            "keyman-samba-rooted-config-missing"
        } else {
            "keyman-samba-password-update-failed"
        };
        failure_receipt("admin-password", false, true, signal, details)
    } else {
        success_receipt("admin-password", false, true, details)
    }
}
