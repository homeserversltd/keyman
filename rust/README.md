# Native Rust Keyman crown verbs

These additions to the Rust `keyman` binary keep the older v1 verbs intact and add native crown operations plus bounded stdin/scoped vault doors. The existing Caduceus staff caller at `sbin/caduceus_staff/keyman.py` remains an OPEN integration dependency; this change does not alter that caller or its wire format. The preserved shell/C field tools are not invoked by the new Rust installer or MGLA technology.

## Native vault verbs

```text
keyman newkey --stdin SERVICE
keyman newkey --stdin SERVICE --replace
keyman export --scoped SERVICE
keyman rotate-suite --stdin
```

`newkey --stdin` accepts exactly `username="<user>"` LF
`password="<password>"` LF, including the final LF and with no trailing bytes.
Each value is nonempty and at most 511 bytes; NUL, CR, LF, and double quote
are refused. There are no escapes, normalization, extra fields, or trailing
bytes. Spaces, `$`, `!`, and Unicode are allowed within the byte limits, and
the accepted bytes are encrypted and exported unchanged. The bounded input
buffer is zeroized.

By default, the key is created exclusively with mode `0600`; an existing file
or symlink is refused. The explicit `--replace` form uses the existing argv
form's safe atomic overwrite semantics and still refuses symlinks. The
exchange directory must be an actual mounted tmpfs even under `KEYMAN_ROOT`.
The existing argv-based `newkey SERVICE USER PASSWORD` form remains for
compatibility.

`export --scoped SERVICE` requires an actual exchange tmpfs and creates
`exchange/SERVICE` exclusively with mode `0600`. It refuses any existing path
and never starts a cleanup child or timer; the caller owns cleanup of its
export. The unscoped export mode and its timer remain unchanged.

`rotate-suite --stdin` reads one bounded JSON object with `current_password`
and `new_password`. It validates and zeroizes the document, checks the current
suite password before mutation, and emits a secret-free native receipt. The
existing argv rotation forms remain unchanged.

Rust `keyman mgla` implements `keygen SERVICE`, `keyline SERVICE`,
`sign SERVICE`, `verify`, and `succeed OLD NEW` natively. It never starts
Python or exports a seed. Credentials remain `username="mgla"` and a
64-character lowercase hex seed as the password, encrypted by the ordinary
Keyman service-key helpers. Seed buffers, credential plaintext, and the
Ed25519 signing key are zeroized on drop, including refusal paths.

`keygen` requires a TTY, refuses CI and existing services, and prints only
`key=<id>` and the public MGLA-KEY1 line. `sign` accepts 1–64 LF-separated
MGLA1 bodies, each at most 16 KiB, with an optional final LF; blank records,
CR and non-printable bytes are refused. It decrypts once and validates every
body and key id before signing or writing any output. Signatures cover the
unchanged body bytes. Mint, sign, and succession emit one bounded metadata
deed line to stderr; no body, seed or signature is logged. `keyline` and
`verify` are reads and emit no deed line.

`verify` needs neither a vault nor root. Stdin is a public MGLA-KEY1 line
followed by one or more attestation lines. It prints VALID, INVALID with a
reason, or UNKNOWN for other MGLA-family formats, as the white paper requires.
Surrounding whitespace and NUL padding are ignored only by verification.
Verification streams bounded records (64 KiB each); an oversized record is
INVALID and does not prevent judging subsequent records. Exit is nonzero
if any record is not VALID. `succeed` retains the old-key-signed MGLA-SUCC1
grammar and refuses identical services or keys.

The preserved direct Python MGLA entry may resolve the
installed `runtime_dir/keyman` binary. A missing binary is refused as
`keyman-rust-binary-missing`; there is no shell or C fallback. The Python
installer builds with `Makefile.rust`, directs output to
`rust/target/keyman-x86_64`, installs the executable as `runtime_dir/keyman`,
and excludes Rust target/cache directories from runtime copying. Its
`--no-build-crypto` compatibility flag requires an existing runtime binary.
Caduceus seed uses the installer's in-process encrypted-key writer, not a
`newkey` command; OpenSSL receives the actual passphrase through stdin.

## Invocation and input

```text
keyman key-status [--device /dev/path]
keyman create-key --target <vault|external|both> --strategy <safe_rotation|replace_primary|flexible_addition>
keyman update-key --device /dev/path --strategy <safe_rotation|replace_primary|flexible_addition>
keyman admin-password
```

`key-status` takes no secret input. The crown mutation verbs read exactly one JSON object from stdin; passwords are never command-line arguments. Inputs reject empty values, NUL, CR, newline, double quote, or values longer than 511 bytes to preserve Keyman’s existing quoted credential-file format. Unknown JSON fields are ignored and zeroized with the parsed document. The optional `planned` field defaults to false when absent or null; a non-boolean non-null value is refused. Illustrative payload shapes use placeholders only and are not runnable credentials:

```json
{"password":"<new password supplied through protected stdin>","planned":true}
{"current_password":"<current password supplied through protected stdin>","planned":true}
{"old_password":"<old password supplied through protected stdin>","new_password":"<new password supplied through protected stdin>","planned":true}
```

Each crown verb emits one JSON object with `ok`, `operation`, `planned`, `changed`, `details`, and `firstMissingSignal`. Failures return nonzero and use the same secret-free receipt shape. Device operations report per-device plans, before/after slot state, partial changes, and the first failure signal. External apply reads the prior NAS credential before rewriting `nas.key`, rewrites it once, exports once through the ephemeral exchange, then attempts every independently observed non-vault device; an error on one mount or device does not suppress another known device. Planned mode reports the NAS rewrite as planned and each device's exact plan, including refusals, without writing. A successful key-file rewrite is reported as `nas_key_rewritten: true` even if a later device fails, with `partial_success: true` when any device fails. Mount-observation and device failures are included in `details.devices[]` with their role. `key-status` is read-only and leaves no disk receipt or status log.

## Slot rules

- The vault birth credential is read only from `root/key/vault-birth.key` (or `/root/key/vault-birth.key` when unrooted). Crown vault operations verify it authenticates LUKS slot 1 before planning or mutation, use that fixed key-file path for vault current-auth mutations, and verify slot 1 still opens afterward. Slot 1 is never replaced or killed.
- `safe_rotation` uses slot 2 when slot 1 is occupied; otherwise it uses slot 1. On the vault, slot 1 is occupied by the verified birth credential, so the operation adds or replaces slot 2.
- `replace_primary` installs the new credential in slot 0, verifies that exact slot opens with the new credential, then removes other enabled slots while preserving slot 1. If the current credential does not authenticate the target slot, replacement is a guarded kill-target/add-target sequence only when another enabled slot still accepts the current credential; otherwise it refuses without removing the target. It never removes the last usable credential during the transition.
- `flexible_addition` adds to the lowest free slot. If none is available, the receipt signal is `keyman-device-slots-full`.
- External-volume changes also preserve an occupied slot 1. `update-key` first tests `current_password` from stdin against the requested device (so an invalid password is reported before a missing `nas.key`), then obtains the replacement NAS credential by decrypting `nas.key` in process.

`create-key --target external|both` reads the previous `nas.key` password before replacing that key through the existing native `newkey` operation. After the write it exports the new NAS credential in process through a locked, one-operation tmpfs exchange: flock the skeleton-key file, create the 0700 exchange directory, mount tmpfs, export/read the key, zero and unlink the export, unmount, remove the directory, then close the lock. No exchange is created for a planned request, and crown export does not launch the legacy delayed-cleanup child.

`admin-password` compares `old_password` in process with the service-suite credential, then rewraps every `vault/.keys/*.key` except `service_suite.key` using the existing AES/PBKDF2 primitives. The plaintext of `caduceus.key` is preserved. It updates only the Unix `owner` password and, when `smbpasswd` exists, the Samba `owner` password. Planned and apply receipts include an ordered, secret-free `details.steps` list naming each rewrapped service (never its value), the suite rewrite, owner password action, Samba presence/result, eligible service restarts or rooted-isolation skips, and rollback outcomes. If `chpasswd` fails, original encrypted key bytes are restored from in-memory buffers; incomplete rollback is reported. Restart failures for installed `ssh.service`, `sshd.service`, or `smbd.service` are reported but are not password-update failures. ROOT credentials, PINs, appliance config, PAM files, and human identity keys are outside this operation.

## Rooted fixture use

`KEYMAN_ROOT=<fixture>` roots Keyman files, device nodes, and account updates. An explicit `KEYMAN_ROOT=/` is refused to prevent fixture escape. Rooted device arguments still use logical `/dev/...` paths, but canonicalize and validate that they resolve to block devices under `<fixture>/dev`. Rooted `chpasswd` uses fixed `--prefix <fixture> --crypt-method SHA512`; the fixture must contain an `owner` account in its passwd/shadow files. If rooted Samba is installed, `<fixture>/etc/samba/smb.conf` must exist as a regular file and is passed using fixed `-c`; the fixture config must direct passdb storage into that fixture. Rooted operations never call the host systemd bus; restart status reports `skipped_rooted_isolation`.

Source or runtime proof belongs in an isolated scratch fixture with dedicated block devices, mounted only inside that proof's namespace. Never aim a fixture request at host devices or live vault/NAS mounts. The JSON examples above contain placeholders, not secrets; do not put credentials in source-control examples, argv, receipts, or logs.

Planned requests inspect actual credentials and slot metadata but perform no writes, including no native `newkey`, LUKS changes, or exchange lifecycle. They create no delayed cleanup process. Apply receipts remain truthful about partial state rather than implying rollback where none occurred.
