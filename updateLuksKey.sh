#!/bin/bash

# Source utility functions
source /vault/keyman/utils.sh

# Function to validate input parameters
validate_input() {
    local drive_name="$1"
    local old_password="$2"
    local new_password="$3"
    
    # Base validation
    if [ -z "$drive_name" ] || [ -z "$old_password" ] || [ -z "$new_password" ]; then
        error_exit "Usage: $0 <drive_name> <old_password> <new_password>"
    fi
    
    # Drive name validation
    if ! [[ "$drive_name" =~ ^nas(_backup)?$ ]]; then
        error_exit "Invalid drive name: $drive_name (must be 'nas' or 'nas_backup')"
    fi
    
    # Password format validation - no longer needed with keyman-crypto
    # keyman-crypto can handle any characters including special symbols
}

# Function to update LUKS encrypted drives
update_luks_drive() {
    local drive_name="$1"
    local old_password="$2"
    local new_password="$3"
    local mount_point
    local source_device
    local backing_device

    # Map drive name to mount point
    case "$drive_name" in
        "nas") mount_point="/mnt/nas" ;;
        "nas_backup") mount_point="/mnt/nas_backup" ;;
        *) error_exit "Invalid drive name for LUKS update: $drive_name" ;;
    esac

    # Device detection logic
    source_device=$(findmnt -n -o SOURCE --target "$mount_point" || error_exit "Could not find source device")
    cryptsetup isLuks "$source_device" || error_exit "Not a LUKS device: $source_device"
    backing_device=$(cryptsetup status "$source_device" | awk '/device:/ {print $2}')

    # Password change with slot enforcement
    echo -e "$old_password\n$new_password" | cryptsetup luksChangeKey "$backing_device" -S 0 || {
        error_exit "Password update failed for $drive_name"
    }

    # Verification steps
    local verify_output=$(echo "$new_password" | cryptsetup open --test-passphrase "$backing_device" 2>&1)
    [ $? -eq 0 ] || error_exit "New password verification failed: $verify_output"

    if echo "$old_password" | cryptsetup open --test-passphrase "$backing_device" 2>/dev/null; then
        error_exit "Security failure: Old password still works"
    fi

    log_message "LUKS password fully rotated for $drive_name (backing device: $backing_device)"
    
    # Also store the new password in the key vault
    "${KEYMAN_DIR}/newkey.sh" "$drive_name" "$drive_name" "$new_password" || \
        error_exit "Failed to update vault key for $drive_name"
        
    echo "Successfully updated LUKS password for $drive_name"
}

# Main script logic
main() {
    local drive_name="$1"
    local old_password="$2"
    local new_password="$3"
    
    validate_input "$drive_name" "$old_password" "$new_password"
    
    # Initialize ramdisk
    init_ramdisk || error_exit "Failed to initialize ramdisk"
    
    # Update LUKS drive password
    update_luks_drive "$drive_name" "$old_password" "$new_password"

    echo "Successfully updated LUKS key for $drive_name"
    exit 0
}

# Execute main with all arguments
main "$@" 