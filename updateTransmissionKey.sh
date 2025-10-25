#!/bin/bash

# Source utility functions
source /vault/keyman/utils.sh

# Function to validate input parameters
validate_input() {
    local new_password="$1"
    local username="$2"
    
    # Base validation
    if [ -z "$new_password" ] || [ -z "$username" ]; then
        error_exit "Usage: $0 <new_password> <username>"
    fi
    
    # Password format validation - no longer needed with keyman-crypto
    # keyman-crypto can handle any characters including special symbols
}

# Function to update Transmission credentials
update_transmission() {
    local new_password="$1"
    local username="$2"
    
    # First stop the transmission-daemon.service to prevent auto-restart issues
    systemctl mask transmission-daemon.service >/dev/null 2>&1 || true
    systemctl stop transmission-daemon.service >/dev/null 2>&1 || true
    
    # Use provided username with newkey.sh
    "${KEYMAN_DIR}/newkey.sh" "transmission" "$username" "$new_password" || {
        # Unmask service before exiting on error
        systemctl unmask transmission-daemon.service >/dev/null 2>&1 || true
        error_exit "Failed to update Transmission credentials"
    }

    # Update both username and password in settings.json
    if ! sed -i -e "s/\"rpc-username\": \".*\"/\"rpc-username\": \"$username\"/" \
                -e "s/\"rpc-password\": \".*\"/\"rpc-password\": \"$new_password\"/" \
                /etc/transmission-daemon/settings.json; then
        # Unmask service before exiting on error
        systemctl unmask transmission-daemon.service >/dev/null 2>&1 || true
        error_exit "Failed to update Transmission settings"
    fi

    # Don't try to restart, just unmask the service
    systemctl unmask transmission-daemon.service >/dev/null 2>&1 || true
    
    # Success message - transmission is managed by transmissionPIA
    echo "Successfully updated credentials for transmission"
}

# Main script logic
main() {
    local new_password="$1"
    local username="$2"
    
    validate_input "$new_password" "$username"
    
    # Initialize ramdisk
    init_ramdisk || error_exit "Failed to initialize ramdisk"
    
    # Update Transmission credentials
    update_transmission "$new_password" "$username"

    echo "Successfully updated Transmission credentials"
    exit 0
}

# Execute main with all arguments
main "$@" 