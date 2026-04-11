# Keyman Key Management

Scripts and crypto for two-tier credential storage: skeleton.key (master) → service_suite.key → per-service keys. Runtime path on homeserver: `/vault/keyman/`. Source: `homeserver/initialization/startup/keyman/`.

## keystartup.sh – Safe manual run vs full deploy

**Do not run `keystartup.sh` without reading this if you are on a development machine or any system that is not a homeserver deploy.** The full flow changes the **admin (owner) user password** and writes to **/deploy/password.txt**. On a random system that can lock you out or overwrite data.

### Safe manual run (skeleton + keys only)

Use this when you want to generate a skeleton key and key material **without** changing any system user password or touching `/deploy`:

```bash
# From a system where keyman is installed under /vault/keyman (e.g. homeserver or after install)
sudo KEYMAN_MANUAL=1 /vault/keyman/keystartup.sh
```

**What this does:**

- Creates `/root/key` and `/vault/.keys` if needed
- If `skeleton.key` is missing: generates a new master password, writes `skeleton.key`, prints it, and does **not** run `chpasswd` or write `/deploy/password.txt`
- If `service_suite.key` is missing: creates it (and NAS key) from the skeleton key (best-effort match of full flow)
- Prints clear warnings that the **full** deploy flow would set the admin (owner) user password to the generated key and write `/deploy/password.txt`

**What this does not do:**

- Does **not** set the root or owner (admin) user password
- Does **not** create or write `/deploy` or `/deploy/password.txt`

**Requirements for manual run:**

- Script sources `/vault/keyman/utils.sh`. Either run on a system where keyman is installed at `/vault/keyman`, or temporarily symlink/copy the keyman tree there, or source `utils.sh` from the repo and set paths (advanced).
- Run as root (script writes to `/root/key` and uses ramdisk at `/mnt/keyexchange`).

### Full deploy flow (homeserver only)

On a real homeserver deploy:

- **Automated:** `AUTOMATED_SETUP=1 /vault/keyman/keystartup.sh` (e.g. from bootstrap). Creates skeleton + service_suite + NAS keys, sets the **owner** user password to the master key (or `DEFAULT_ROOT_PASSWORD`), writes `/deploy/password.txt`.
- **Interactive (recovery):** Run as root without `KEYMAN_MANUAL=1`. If `/deploy` exists, the script will set the owner password and write `/deploy/password.txt`. If `/deploy` does not exist, the script **does not** set any password (defensive); it only creates keys and warns.

So: on a non-deploy machine, either use **KEYMAN_MANUAL=1** or rely on the script’s guard (no `/deploy` → no `chpasswd`/no `/deploy` write).

### Environment variables

| Variable | Effect |
|----------|--------|
| `KEYMAN_MANUAL=1` | Safe manual mode: create skeleton (+ keys) only; never set admin password or write /deploy |
| `AUTOMATED_SETUP=1` | Automated first-time setup (skeleton + keys + set owner password + /deploy/password.txt when not KEYMAN_MANUAL) |
| `DEFAULT_ROOT_PASSWORD` | When set in full deploy mode, owner user gets this password instead of the skeleton key (misnomer: it is the admin/owner password, not root) |
| `TEST_FLAG=1` | Skips setting admin password even in full deploy (for tests) |

### newkey.sh – Create a per-service credential (full manual)

Use this after the key hierarchy exists (`skeleton.key` + `service_suite.key`). It stores **username + password** for one logical service under a single encrypted file named after the service.

### Prerequisites

1. **Install layout:** Keyman lives at `/vault/keyman/` with `utils.sh`, `newkey.sh`, and the `keyman-crypto` binary. From repo source: `make` builds `keyman-crypto`; `sudo make install` copies **only** that binary into `/vault/keyman/` (see `Makefile`). Ensure the shell scripts from the same tree are present there too (copy/rsync from `homeserver/initialization/startup/keyman/` as your deploy does).
2. **Hierarchy initialized:** Both must exist:
   - `/root/key/skeleton.key` (master)
   - `/vault/.keys/service_suite.key` (encrypted with the skeleton)
   If not, run `keystartup.sh` first (typically `KEYMAN_MANUAL=1` on a non-deploy machine; see above).
3. **Run as root:** The script mounts a tmpfs at `/mnt/keyexchange` and writes `/vault/.keys/<service>.key`.

### Syntax (exactly three arguments)

```bash
sudo /vault/keyman/newkey.sh <service_name> <username> <password>
```

| Argument | Rules |
|----------|--------|
| `<service_name>` | Only letters, digits, and underscores: `^[a-zA-Z0-9_]+$`. This becomes the filename stem: `/vault/.keys/<service_name>.key`. |
| `<username>` | Stored as the credential username (no `^[a-zA-Z0-9_]+$` check on this field in `newkey.sh`). |
| `<password>` | Passed through to `keyman-crypto create`; quote it for the shell (see below). |

### What happens (order of operations)

1. `source /vault/keyman/utils.sh`
2. Validate `<service_name>`; exit with usage if the argument count is not 3.
3. `init_ramdisk`: ensure `/mnt/keyexchange` is a writable tmpfs (creates or reuses mount).
4. Write a short-lived file under the ramdisk with lines `service=…`, `username=…`, `password=…`.
5. Run `/vault/keyman/keyman-crypto create <that_file>` (AES-256-CBC + PBKDF2 using the service suite key material).
6. Shred the temp input file and run `secure_cleanup` (clears ramdisk work area).

**On-disk result:** encrypted credential at `/vault/.keys/<service_name>.key`. The C helper opens this path with write mode: **an existing file for the same service name is overwritten** with no prompt.

### Quoting and special characters in the password

Use **single quotes** so the shell does not expand `$`, backticks, or spaces:

```bash
sudo /vault/keyman/newkey.sh vaultwarden 'admin@home.arpa' 'p4ss w0rd! with ${weird}'
```

If the password itself contains a single quote, you cannot wrap the whole password in single quotes only; use one of: `'\''` inside single-quoted segments, or pass the password from a variable set in a subshell/file you control.

### Verify (read back)

```bash
sudo /vault/keyman/exportkey.sh <service_name>
```

On success, decrypted content is placed under `/mnt/keyexchange/` (see `exportkey.sh`); a cleanup timer clears the ramdisk. Inspect the file there immediately if you need to confirm username/password.

### Example (end-to-end)

```bash
# 1) Ensure hierarchy exists (once per machine)
sudo KEYMAN_MANUAL=1 /vault/keyman/keystartup.sh

# 2) Store a credential for a service named myapp_db (name must match regex ^[a-zA-Z0-9_]+$)
sudo /vault/keyman/newkey.sh myapp_db 'appuser' 'SuperSecret123'

# 3) Confirm
sudo /vault/keyman/exportkey.sh myapp_db
```

### Debugging

- `DEBUG=true` on the same command line enables verbose logging (via `utils.sh`).
- `BENCHMARK=true` logs timing to the benchmark log path when enabled in `utils.sh`.

### Operational notes

- Passing the password as the third argument is **simple but not secret from the local shell**: it may appear in shell history and was visible in the process list while the command ran. For air-gapped or policy reasons, plan accordingly (the script does not read from stdin for the password).
- **Admin / symlink keys:** Some flows use a symlink to `service_suite.key` instead of a dedicated `newkey` entry (see `newkey.sh` internal `adminkey` mode in other scripts). For a normal app credential, use `newkey.sh` as above.

## Summary

- **Manual run on dev / unknown system:** Use `KEYMAN_MANUAL=1` so the script only creates a skeleton key and keys, with warnings that the real deal sets owner and /deploy.
- **Full flow** sets the **owner** (admin) user password and writes `/deploy/password.txt`; it does **not** set the root password. Root is unchanged.

For other keyman commands (exportkey, deletekey, change_service_suite_key, LUKS/Transmission), see the Keyman component skill (`.cursor/skills/homeserver-components-keyman/SKILL.md`).
