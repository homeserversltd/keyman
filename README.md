# Keyman Credential Management Suite v1.0.0

Enterprise-grade credential management system providing secure, encrypted storage and access to service credentials using AES-256-CBC encryption.

## Architecture

**Two-Tier Encryption Hierarchy:**
```
skeleton.key (master password) → service_suite.key → individual service credentials
```

**Components:**
- **keyman-crypto**: C binary for cryptographic operations (AES-256-CBC + PBKDF2)
- **Shell Scripts**: High-level credential management utilities  
- **utils.sh**: Shared functions and configuration

## Quick Reference

### Core Operations
```bash
# Create service credentials (any service name)
newkey.sh <service_name> <username> <password>

# Export credentials to ramdisk (15s auto-cleanup)
exportkey.sh <service_name>

# Delete credentials (interactive menu)
deletekey.sh

# Initialize system (run once as root)
keystartup.sh
```

### Key Management
```bash
# Rotate encryption key for ALL services
change_service_suite_key.sh

# Update LUKS drive passwords  
updateLuksKey.sh <drive_name> <old_password> <new_password>

# Update Transmission credentials
updateTransmissionKey.sh <new_password> <username>
```

## File Structure

**Scripts:**
- `keyman-crypto.c` - Cryptographic engine source
- `keyman-crypto` - Compiled binary (build with `make`)
- `Makefile` - Build configuration
- `utils.sh` - Shared utilities
- `newkey.sh` - Create credentials
- `exportkey.sh` - Export to ramdisk
- `change_service_suite_key.sh` - Rotate encryption keys
- `updateTransmissionKey.sh` - Transmission-specific updates
- `updateLuksKey.sh` - LUKS drive management  
- `deletekey.sh` - Remove credentials
- `keystartup.sh` - System initialization

**Storage Locations:**
```
/root/key/skeleton.key              # Master password (plaintext)
/vault/.keys/service_suite.key      # Encryption key (encrypted)
/vault/.keys/<service>.key          # Service credentials (encrypted)
/mnt/keyexchange/                   # Temporary export location (ramdisk)
```

## Security Features

- **Encryption**: AES-256-CBC with PBKDF2 key derivation
- **Runtime Protection**: Ramdisk-based access with automatic cleanup
- **Access Control**: Restricted permissions (600/700), root-only access
- **Memory Safety**: Secure cleanup in C binary, no persistent decrypted storage

## Building & Installation

```bash
# Install dependencies (Arch Linux)
sudo pacman -S gcc openssl

# Build and install
make && sudo make install
```

## Generic Service Support

The system supports **any service name** - no predefined services required. Service names must be alphanumeric with underscores only. All services receive identical treatment.

## Environment Variables

```bash
DEBUG=true          # Enable debug logging
BENCHMARK=true      # Enable timing metrics  
AUTOMATED_SETUP=1   # Enable automated keystartup mode
```

## Error Recovery

| Issue | Solution |
|-------|----------|
| Lost master password | Delete `skeleton.key`, run `keystartup.sh`, recreate all credentials |
| Lost service suite key | Delete `service_suite.key`, run `keystartup.sh`, recreate all credentials |
| Corrupted service credentials | Delete specific `.key` file, recreate with `newkey.sh` |

## Usage Examples

```bash
# Enterprise workflow
newkey.sh jellyfin admin SecurePass123
newkey.sh vaultwarden vault_admin VaultPass456
exportkey.sh jellyfin  # Available at /mnt/keyexchange/jellyfin

# Custom applications
newkey.sh my_app service_user MyAppPass789
exportkey.sh my_app

# Key rotation (affects all services)
change_service_suite_key.sh --non-interactive current_pass new_pass
```

## Professional Deployment Notes

- Designed for production environments requiring credential isolation
- Supports enterprise services (Jellyfin, Transmission, Vaultwarden, etc.)
- Generic architecture allows integration with custom applications
- Automated setup suitable for deployment scripts
- Comprehensive logging and benchmarking for operations teams

