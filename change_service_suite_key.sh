#!/bin/bash

# Source the utility functions
source /vault/keyman/utils.sh

# Function to display usage information
show_usage() {
    echo "Usage: $0 [--non-interactive <current_password> <new_password>]"
    echo ""
    echo "Options:"
    echo "  --non-interactive   Run in non-interactive mode, reading passwords from command-line"
    echo "                      instead of prompting (for automation)"
    echo ""
    echo "Arguments for non-interactive mode:"
    echo "  <current_password>  The current service suite password"
    echo "  <new_password>      The new service suite password"
    echo ""
    echo "Example:"
    echo "  $0 --non-interactive 'currentpass' 'newpass'"
    echo ""
    echo "Warning: Using command-line arguments may expose passwords in process lists"
    echo "         and shell history. Use with caution."
    exit 1
}

# Function to re-encrypt all service credentials with new key
reencrypt_service_credentials() {
    local benchmark_start=""
    if [ "$BENCHMARK" = "true" ]; then
        benchmark_start=$(date +%s.%N)
    fi

    local old_password="$1"  # Keep old_password argument for clarity, though exportkey uses the current service_suite key implicitly
    local new_password="$2"
    local error_count=0
    local success_count=0
    local failed_services=""

    # Initialize ramdisk (exportkey.sh also does this, but good practice here)
    time_operation init_ramdisk || error_exit "Failed to initialize ramdisk"

    # Decrypt all service keys using exportkey.sh first
    echo "Attempting to decrypt all service keys using exportkey.sh..."
    for key_file in "$VAULT_DIR"/*.key; do
        # Skip service suite key itself
        if [ "$(basename "$key_file")" = "$(basename "$SERVICE_SUITE_KEY")" ]; then
            continue
        fi

        local service_name=$(basename "$key_file" .key)
        echo "Exporting/Decrypting $service_name..."

        # Call exportkey.sh to handle decryption into TEMP_DIR
        if ! time_operation /vault/keyman/exportkey.sh "$service_name"; then
            # exportkey.sh already logs errors, but we'll log here too and track failure
            echo "Failed to export/decrypt $service_name using exportkey.sh"
            ((error_count++))
            failed_services+="$service_name (export/decrypt), "
            # Do not continue to re-encryption for this service
            continue
        fi
        echo "Successfully exported/decrypted $service_name to $TEMP_DIR"
    done

    if [ $error_count -gt 0 ]; then
        # Trim trailing comma and space
        failed_services=${failed_services%, }
        error_exit "Initial decryption failed for: $failed_services. Cannot proceed with re-encryption."
    fi

    # Now, re-encrypt decrypted files from TEMP_DIR with the new key
    echo "Re-encrypting services with the new key..."
    error_count=0 # Reset error count for re-encryption phase
    failed_services="" # Reset failed services list

    for key_file in "$VAULT_DIR"/*.key; do
         # Skip service suite key itself
        if [ "$(basename "$key_file")" = "$(basename "$SERVICE_SUITE_KEY")" ]; then
            continue
        fi

        local service_name=$(basename "$key_file" .key)
        local decrypted_file="$TEMP_DIR/$service_name"

        # Check if the decrypted file exists (it should if export was successful)
        if [ ! -f "$decrypted_file" ]; then
            echo "Error: Decrypted file $decrypted_file not found for $service_name. Skipping re-encryption."
            ((error_count++))
            failed_services+="$service_name (missing decrypted), "
            continue
        fi

        echo "Re-encrypting $service_name..."

        # Create input file for keyman-crypto reencrypt operation
        local reencrypt_input="$TEMP_DIR/reencrypt_input.$$"
        printf 'service=%s\nnew_password=%s\n' "$service_name" "$new_password" > "$reencrypt_input"
        
        # Re-encrypt with new key using keyman-crypto
        if ! time_operation /vault/keyman/keyman-crypto reencrypt "$reencrypt_input"; then
            echo "Failed to re-encrypt $service_name"
            ((error_count++))
            failed_services+="$service_name (encrypt), "
            # Clean up temporary input file
            shred -u "$reencrypt_input" 2>/dev/null || rm -f "$reencrypt_input"
            continue
        fi
        
        # Clean up temporary input file
        shred -u "$reencrypt_input" 2>/dev/null || rm -f "$reencrypt_input"

        # Securely remove the decrypted file from TEMP_DIR after successful re-encryption
        shred -u "$decrypted_file" 2>/dev/null || echo "Warning: Failed to securely remove decrypted file $decrypted_file"


        ((success_count++))
        echo "Successfully re-encrypted $service_name"
    done


    if [ "$BENCHMARK" = "true" ] && [ -n "$benchmark_start" ]; then
        benchmark_log "$benchmark_start" "Total re-encryption of all services"
    fi

    echo "Re-encryption complete. Success: $success_count, Failures: $error_count"

    if [ $error_count -gt 0 ]; then
        # Trim trailing comma and space
        failed_services=${failed_services%, }
        error_exit "Failed to re-encrypt the following services: $failed_services"
    fi

    return 0
}

# Parse command-line arguments for non-interactive mode
INTERACTIVE=true
if [ "$1" = "--non-interactive" ]; then
    INTERACTIVE=false
    
    # Require exactly 3 arguments (command + 2 passwords)
    if [ $# -ne 3 ]; then
        echo "Error: Non-interactive mode requires both current and new passwords"
        show_usage
    fi
    
    input_password="$2"
    new_password="$3"
    
    # Basic validation
    if [ -z "$input_password" ] || [ -z "$new_password" ]; then
        echo "Error: Empty passwords are not allowed"
        exit 1
    fi
    
    echo "Running in non-interactive mode"
    echo "Input password length: ${#input_password}"
    echo "New password length: ${#new_password}" 
    
    # Display each character in the new password for debugging
    echo "New password characters:"
    for (( i=0; i<${#new_password}; i++ )); do
        char="${new_password:$i:1}"
        printf "Char %d: '%s' (ASCII: %d)\n" "$i" "$char" "'$char"
    done
fi

# Check if key system is initialized
check_key_system_initialized

# Get current service suite key
if ! get_service_suite_key; then
    error_exit "Failed to get service suite key"
fi

# Get current password from service suite key
current_password=$(grep 'password=' "$TEMP_DIR/service_suite" | cut -d'"' -f2)

if [ "$INTERACTIVE" = "true" ]; then
    # Interactive mode: prompt for passwords
    # Prompt for current password
    read -s -p "Enter current service suite password: " input_password
    echo

    # Verify password matches
    if [ "$input_password" != "$current_password" ]; then
        unset input_password current_password
        secure_cleanup
        error_exit "Invalid password"
    fi

    # Prompt for new password
    read -s -p "Enter new service suite password: " new_password
    echo
    read -s -p "Confirm new service suite password: " confirm_password
    echo

    if [ "$new_password" != "$confirm_password" ]; then
        unset new_password confirm_password current_password
        secure_cleanup
        error_exit "Passwords do not match"
    fi
    
    unset confirm_password
else
    # Non-interactive mode: verify provided current password
    if [ "$input_password" != "$current_password" ]; then
        unset input_password current_password
        secure_cleanup
        error_exit "Invalid password"
    fi
fi

# Password format validation - no longer needed with keyman-crypto
# keyman-crypto can handle any characters including special symbols

# Re-encrypt all service credentials with new key
if ! reencrypt_service_credentials "$current_password" "$new_password"; then
    unset new_password input_password current_password
    error_exit "Failed to re-encrypt some service credentials"
fi

# Update the service suite key with new password
echo "username=\"service_suite\"" > "$TEMP_DIR/service_suite"
echo "password=\"$new_password\"" >> "$TEMP_DIR/service_suite"

# Encrypt with master password using keyman-crypto
time_operation /vault/keyman/keyman-crypto encrypt_suite_key "$TEMP_DIR/service_suite"

# Clean up
unset new_password input_password current_password

echo "Service suite key has been updated successfully."
echo "All service credentials have been re-encrypted with the new key."

exit 0