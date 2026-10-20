# Keyman installer band

The Python installer remains the public install front door, but new runtime
technology uses the Rust Keyman binary. Installation builds it with
`Makefile.rust`, directs the artifact to `rust/target/keyman-x86_64` (inside
the ignored Rust target tree), and installs it as `runtime_dir/keyman`.
Runtime copying excludes Rust target/cache directories. No generic `make`, C
binary, shell-script, or `PATH` fallback is used. The compatibility flag
`--no-build-crypto` skips the Rust build and requires an existing executable at
the declared runtime path.

```text
python3 index.py plan --profile vault-only
sudo python3 index.py install --profile vault-only
python3 index.py rotate --dry-run --profile vault-only
```

`KEYMAN_ROOT`, when set, must be an existing canonical absolute non-root
directory. The installer maps its default Keyman runtime, key, vault, exchange,
deploy-secret, and SSH paths beneath that root. Custom path overrides that
cannot be mapped to the Rust fixed paths are refused before mutation; they are
never ignored or allowed to fall back to live paths.

The Caduceus seed is written by the existing `_write_encrypted_key` method,
not by a `newkey.sh` ceremony. It preserves the SHA-256 identity derived from
the raw skeleton-key bytes and encrypts with the actual service-suite password.
The passphrase is delivered to OpenSSL on stdin using `-pass stdin` and is not
put in argv or environment variables.

Service-suite rotation invokes `runtime_dir/keyman rotate-suite --stdin` with
one bounded JSON object on stdin. The Rust verb validates and compares the
current service-suite password before changing keys; the installer suppresses
child stdout/stderr and returns only a named, secret-free refusal.

The MGLA band uses only native Rust `keyman newkey --stdin SERVICE` and
`keyman export --scoped SERVICE`. Its lock, TTY/CI restrictions, exclusive
creation, exchange-tmpfs requirement, and process-owned export cleanup remain
in force. Neither this installer nor the MGLA band invokes the old shell/C
field tools. Those files remain byte-preserved for legacy field updater use;
see root `MIGRATED.txt`.
