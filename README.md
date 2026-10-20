# Keyman credential management

Keyman keeps a skeleton key, a service-suite key, and per-service encrypted
credentials. New installation and MGLA technology use the Rust Keyman binary;
the preserved shell/C tools are legacy field-only compatibility files.

## Modern installer and runtime

The Python entry point remains the installer and MGLA staff face:

```text
python3 index.py plan --profile vault-only
sudo python3 index.py install --profile vault-only
python3 index.py rotate --dry-run --profile vault-only
```

A normal install builds with `make -f Makefile.rust` and supplies the resulting
Rust executable as `runtime_dir/keyman` (default `/vault/keyman/keyman`). The
installer directs the build output to the ignored
`rust/target/keyman-x86_64`; it excludes Rust target/cache directories from
runtime copying. `--no-build-crypto` is retained for compatibility: it skips
the Rust build and requires an existing executable at the declared runtime
path. There is no generic `make`, C-binary, shell, or `PATH` fallback.

The installer seeds `caduceus.key` through its existing in-process
`_write_encrypted_key` writer. Its username remains the SHA-256 digest of the
raw skeleton-key bytes, and its encrypted file uses the actual service-suite
password, including after suite rotation. Service-suite rotation runs the
native `keyman rotate-suite --stdin` verb; its JSON credentials travel only on
stdin, not in command arguments or environment variables.

When `KEYMAN_ROOT` is set, it must be an existing canonical absolute
non-root directory. Python maps the Keyman runtime, key, vault, exchange, and
installer paths beneath that root to the same fixed Rust paths. Unmappable
custom path overrides are refused before mutation; they are never ignored and
never fall back to live paths.

## Native credential doors

The Rust binary retains the existing `keyman newkey SERVICE USER PASSWORD`
argument form for compatibility. The bounded MGLA form is:

```text
keyman newkey --stdin SERVICE
```

It accepts exactly 70 bytes: `mgla\n`, 64 lowercase hexadecimal seed bytes,
and one final newline, with no trailing byte. The seed is bounded and
zeroized. The service key is created exclusively with mode `0600`; existing
files and symlinks are refused. The exchange directory must be an actual
mounted tmpfs, including under `KEYMAN_ROOT`.

The scoped export form is:

```text
keyman export --scoped SERVICE
```

It requires the actual exchange tmpfs, creates `exchange/SERVICE` exclusively
with mode `0600`, refuses any pre-existing artifact, and starts no cleanup
child or timer. The caller owns removal of the exact export it created. The
legacy unscoped `keyman export SERVICE` form and its cleanup timer remain
unchanged for field compatibility.

The bounded rotation form reads one JSON object from stdin:

```text
keyman rotate-suite --stdin
```

The object contains `current_password` and `new_password`; both are bounded,
validated, and zeroized. The native command verifies the current suite
password before mutation. Existing argv rotation forms remain available for
compatibility.

The Rust MGLA launcher passes its resolved executable path to Python as
`KEYMAN_BINARY`. Direct Python MGLA may resolve only the configured runtime
binary (`runtime_dir/keyman`). A missing or invalid binary produces the named
`keyman-rust-binary-missing` refusal. MGLA never shells out to the old scripts.

MGLA operations are:

```text
keyman mgla keygen SERVICE
keyman mgla keyline SERVICE
keyman mgla sign SERVICE          # exact MGLA1 body on stdin
keyman mgla succeed OLD NEW
```

`keygen` keeps its TTY and CI refusals. It sends the private seed only through
`newkey --stdin`; keyline, sign, and succession obtain private material only
through `export --scoped`. MGLA retains its skeleton-file lock, exclusive
credential checks, scoped cleanup, and secret-free output.

## Legacy field-only compatibility (unchanged bytes)

`keystartup.sh`, `newkey.sh`, `exportkey.sh`, `deletekey.sh`,
`change_service_suite_key.sh`, `updateLuksKey.sh`,
`updateTransmissionKey.sh`, `utils.sh`, `keyman-crypto.c`, the legacy
`Makefile`, and the existing C binary remain in place for already-deployed
field updaters. They are not invoked by the new installer, Rust verbs, or MGLA
module. The migration map is recorded in `MIGRATED.txt`; old field-only
material is retained rather than deleted or rewritten.
