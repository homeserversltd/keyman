# Keyman installer band

This band is the forward-only Python installer for Keyman. It keeps the old C
crypto helper and shell tools alive, but moves installation policy into explicit
profiles and flags.

Important profiles:

- `vault-only`: install/runtime initialize Keyman without changing system
  account secrets.
- `field-node`: set the configured operator account for local TTY access when
  an access secret is explicitly supplied, keep SSH interactive authentication
  disabled, and initialize the Keyman vault without writing the deploy secret
  file.
- `full-deploy`: compatibility full deploy posture for the original full-system
  lane.

Run from the Keyman repo root:

```bash
python3 index.py
python3 index.py plan --profile field-node --admin-secret-env KEYMAN_ADMIN_SECRET
sudo KEYMAN_ADMIN_SECRET='<operator-local-secret>' python3 index.py install --profile field-node --admin-secret-env KEYMAN_ADMIN_SECRET
```

Receipts redact secret material.
