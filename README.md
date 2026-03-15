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

### Summary

- **Manual run on dev / unknown system:** Use `KEYMAN_MANUAL=1` so the script only creates a skeleton key and keys, with warnings that the real deal sets owner and /deploy.
- **Full flow** sets the **owner** (admin) user password and writes `/deploy/password.txt`; it does **not** set the root password. Root is unchanged.

For other keyman commands (newkey, exportkey, deletekey, change_service_suite_key, LUKS/Transmission), see the Keyman skill (`.cursor/skills/keyman/SKILL.md`) and the main startup README.
