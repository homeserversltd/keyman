# Keyman Credential Management Suite

## Key Hierarchy Overview

The Keyman suite uses a two-tier encryption hierarchy:

```
skeleton.key (master password)
    └── encrypts service_suite.key
        └── encrypts all service credential files
```

### 1. Master Password (skeleton.key)
- Located at `/root/key/skeleton.key`
- Top-level encryption key
- Used to encrypt/decrypt the service suite key
- Also used as default system password unless overridden
- **CRITICAL**: If lost, all encrypted data becomes inaccessible

### 2. Service Suite Key (service_suite.key)
- Located at `/vault/.keys/service_suite.key`
- Encrypted with the master password
- Used to encrypt/decrypt all service credential files
- Can be rotated without changing the master password
- Rotation requires re-encrypting all service credentials

### 3. Service Credentials
- Located at `/vault/.keys/<service>.key`
- Each service has its own encrypted credential file
- All encrypted using the service suite key
- Contains username/password pairs in shell format

## Key Management Scripts

**IMPORTANT:** The keyman system is designed to be completely generic. You can create and manage credentials for ANY service - not just predefined ones. All services are treated equally with no special handling.

### 1. newkey.sh
Creates new service credentials for ANY service:
```bash
# Create new service credentials
newkey.sh <service_name> <username> <password>

# Examples:
newkey.sh jellyfin admin MySecurePass123
newkey.sh transmission user TransmissionPass456
newkey.sh custom_service some_user AnotherPass789
```

**Requirements:**
- `service_name`: Only alphanumeric characters and underscores allowed
- `password`: Can contain any characters including letters, numbers, and special symbols

### 2. exportkey.sh
Exports decrypted credentials to ramdisk for ANY service:
```bash
# Export credentials for service use
exportkey.sh <service_name>

# Examples:
exportkey.sh jellyfin
exportkey.sh transmission
exportkey.sh custom_service

# Credentials available at /mnt/keyexchange/<service_name>
# Automatically cleaned up after 15 seconds of inactivity
```

**Note:** Can export any service that has a corresponding `.key` file in `/vault/.keys/`

### 3. change_key.sh
Updates existing service credentials:
```bash
# Update service credentials
change_key.sh <service> <new_password> [username] [old_password]

# Examples:
change_key.sh jellyfin "new_password" "admin"
change_key.sh transmission "new_pass" "user" "old_pass"
```

Special handling for:
- LUKS encrypted drives (nas, nas_backup) - requires old password
- Transmission daemon settings - requires username parameter

### 4. updateTransmissionKey.sh
Specialized script for updating Transmission credentials:
```bash
# Update Transmission credentials (no old password needed)
updateTransmissionKey.sh <new_password> <username>

# Example:
updateTransmissionKey.sh "NewTransPass789" "transmission_user"
```

### 5. updateLuksKey.sh
Specialized script for updating LUKS encrypted drive passwords:
```bash
# Update LUKS drive password
updateLuksKey.sh <drive_name> <old_password> <new_password>

# Examples:
updateLuksKey.sh nas "old_password" "new_password"
updateLuksKey.sh nas_backup "old_backup_pass" "new_backup_pass"
```

### 6. change_service_suite_key.sh
Manages the encryption key for all services:
```bash
# Interactive mode
change_service_suite_key.sh

# Non-interactive mode (for automation)
change_service_suite_key.sh --non-interactive <current_password> <new_password>
```

This script:
1. Decrypts all service credentials with old key
2. Generates new service suite key
3. Re-encrypts all service credentials with new key
4. Re-encrypts service suite key with master password

### 7. deletekey.sh
Removes service credentials:
```bash
# Interactive menu to select and delete credentials
deletekey.sh
```

### 8. keystartup.sh
Initializes the key system:
```bash
# Initialize key system (run as root)
keystartup.sh
```

### 9. setRoot.sh
Sets root password from skeleton key:
```bash
# Set root password to match skeleton key
setRoot.sh
```

## Storage Locations

```
/root/key/
└── skeleton.key           # Master password (plaintext)

/vault/.keys/
├── service_suite.key      # Encryption key (encrypted with master password)
└── <service>.key         # Service credentials (encrypted with service suite key)

/mnt/keyexchange/         # Temporary decrypted credentials (ramdisk)
```

## Security Features

### 1. Encryption
- AES-256-CBC with PBKDF2
- Two-tier encryption hierarchy
- Individual service encryption

### 2. Runtime Protection
- Ramdisk-based credential access (`/mnt/keyexchange`)
- Automatic cleanup timer (15-second inactivity)
- No persistent decrypted storage
- Secure file deletion with `shred`

### 3. Access Control
- File permissions (0o600 for keys)
- Directory restrictions (0o700)
- Secure key exchange via ramdisk

### 4. Password Validation
Passwords must contain only:
- Uppercase letters: A-Z
- Lowercase letters: a-z  
- Numbers: 0-9
- Symbols: `-._~`
- Underscore: `_`

**Note:** The error message in the code mentions `@#%+-` but the actual validation uses `-._~`. This is a known discrepancy.

## Environment Variables

### Debug and Benchmarking
- `DEBUG=true`: Enable debug logging
- `BENCHMARK=true`: Enable timing metrics
- `BENCHMARK_LOG`: Path for benchmark logs (default: `/mnt/ramdisk/logs/benchmark.log`)

### Setup and Automation
- `AUTOMATED_SETUP=1`: Enable automated mode for keystartup.sh
- `DEFAULT_ROOT_PASSWORD`: Override default system password
- `TEST_FLAG=1`: Enable test mode (prevents password changes)

## Common Operations

### 1. Creating New Service Credentials
```bash
# Create new service credentials for ANY service
newkey.sh <service_name> <username> <password>

# Examples:
newkey.sh jellyfin admin MySecurePass123
newkey.sh transmission user TransmissionPass456
newkey.sh custom_app some_user AnotherPass789
newkey.sh whatever_service admin ValidPass123
```

**Key Points:**
- Can create credentials for any service name (alphanumeric + underscores only)
- All services are treated equally - no special handling
- Password must match validation rules: `A-Z`, `a-z`, `0-9`, `_`, `-`, `.`, `~`

### 2. Accessing Credentials
```bash
# Export credentials for ANY service
exportkey.sh <service_name>

# Examples:
exportkey.sh jellyfin
exportkey.sh transmission
exportkey.sh custom_app
exportkey.sh whatever_service

# Credentials available at /mnt/keyexchange/<service_name>
# Format: username="user" password="pass"
```

**Key Points:**
- Can export any service that has a `.key` file in `/vault/.keys/`
- All services use the same export process
- Special case: `service_suite` uses skeleton key, others use service suite key

### 3. Updating Service Credentials
```bash
# Update existing service credentials
change_key.sh <service> <new_password> [username] [old_password]

# Examples:
change_key.sh jellyfin "new_password" "admin"
change_key.sh transmission "new_pass" "user" "old_pass"
```

### 4. Deleting Credentials
```bash
# Remove service credentials (interactive)
deletekey.sh
```

### 5. Key Rotation
Two types of rotation available:

1. **Service Credential Rotation**:
```bash
# Only changes one service's credentials
change_key.sh <service> <new_password> [username] [old_password]
```

2. **Encryption Key Rotation**:
```bash
# Re-encrypts ALL service credentials with new key
change_service_suite_key.sh
```

### 6. LUKS Drive Management
```bash
# Update LUKS drive passwords
updateLuksKey.sh <drive_name> <old_password> <new_password>

# Examples:
updateLuksKey.sh nas "old_password" "new_password"
updateLuksKey.sh nas_backup "old_backup_pass" "new_backup_pass"
```

### 7. Transmission Management
```bash
# Update Transmission credentials
updateTransmissionKey.sh <new_password> <username>

# Example:
updateTransmissionKey.sh "NewTransPass789" "transmission_user"
```

## Error Recovery

### 1. Lost Master Password
- All data must be considered lost
- Delete skeleton.key
- Run keystartup.sh to generate new master password
- Recreate all service credentials

### 2. Lost Service Suite Key
- Delete service_suite.key
- Run keystartup.sh to generate new key
- Recreate all service credentials

### 3. Lost Service Credentials
- Delete specific <service>.key
- Use newkey.sh to recreate credentials

### 4. Corrupted Key Files
- Delete the corrupted key file
- Recreate using newkey.sh
- For service_suite.key corruption, see "Lost Service Suite Key"

## Testing

### Test Suite
Run the comprehensive test suite:
```bash
# Basic test
sudo ./test_keyman.sh

# With debug output
sudo DEBUG=true ./test_keyman.sh

# With timing metrics
sudo BENCHMARK=true ./test_keyman.sh
```

### Manual Testing
```bash
# Test key creation for any service
newkey.sh test_service test_user TestPass123
newkey.sh another_test admin AnotherPass456
newkey.sh custom_app user CustomPass789

# Test key export for any service
exportkey.sh test_service
exportkey.sh another_test
exportkey.sh custom_app

# Test key rotation
change_key.sh test_service NewTestPass456 test_user TestPass123

# Clean up
deletekey.sh  # Select services from menu
```

**Note:** The system is designed to handle any service name, making it perfect for testing custom applications or services.

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure running as root
   - Check file permissions (should be 600 for keys, 700 for directories)

2. **Ramdisk Mount Failed**
   - Check if `/mnt/keyexchange` is already mounted
   - Verify tmpfs is available
   - Check available memory

3. **Decryption Failed**
   - Verify skeleton.key exists and is readable
   - Check service_suite.key integrity
   - Ensure correct password format

4. **Cleanup Timer Issues**
   - Check `/mnt/ramdisk/keyman_timer.pid`
   - Verify timer process is running
   - Manual cleanup: `umount /mnt/keyexchange`

### Debug Mode
Enable debug logging for troubleshooting:
```bash
export DEBUG=true
# Run any keyman script to see detailed logs
```

### Benchmark Mode
Enable timing metrics for performance analysis:
```bash
export BENCHMARK=true
# Run scripts to see timing data in /mnt/ramdisk/logs/benchmark.log
```

