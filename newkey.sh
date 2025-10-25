#!/bin/bash

# Source the utility functions
source /vault/keyman/utils.sh

# Initialize timing variables
total_start=""

prompt_password(){
    local prompt_start=""
    if [ "$BENCHMARK" = "true" ]; then
        prompt_start=$(date +%s.%N)
    fi

    echo "Password must contain only alphanumeric characters, underscores, and the following symbols: @#%+-"
    read -r password

    if [[ "$password" =~ ^[a-zA-Z0-9_@#%+\-]+$ ]]; then
        debug_log "Password validation successful"
        if [ "$BENCHMARK" = "true" ] && [ -n "$prompt_start" ]; then
            benchmark_log "$prompt_start" "Password prompt and validation"
        fi
        echo "$password"
        return 0
    else
        echo "Input contains disallowed characters"
        return 1
    fi
}

# Function to handle key generation based on mode
handle_key_generation() {
    local gen_start=""
    if [ "$BENCHMARK" = "true" ]; then
        gen_start=$(date +%s.%N)
    fi

    local mode="$1"
    local service_name="$2"
    local manual_password="$3"
    local password
    
    case "$mode" in
        "random")
            debug_log "Generating random password"
            password=$(generate_random_key)
            ;;
        "adminkey")
            debug_log "Creating symlink to service suite key"
            # Fast path - just create symlink and return
            ln -sf "$SERVICE_SUITE_KEY" "$VAULT_DIR/${service_name}.key" || {
                error_exit "Failed to create symlink for $service_name"
                return 1
            }
            debug_log "Successfully created symlink for $service_name"
            return 0
            ;;
        "manual")
            debug_log "Using provided manual password"
            if [ -z "$manual_password" ]; then
                error_exit "Manual password not provided"
                return 1
            fi
            if ! validate_manual_password "$manual_password"; then
                error_exit "Manual password contains invalid characters"
                return 1
            fi
            password="$manual_password"
            ;;
        *)
            error_exit "Invalid mode: $mode"
            return 1
            ;;
    esac
    
    if [ -n "$password" ]; then
        debug_log "Password generation successful"
        if [ "$BENCHMARK" = "true" ] && [ -n "$gen_start" ]; then
            benchmark_log "$gen_start" "Key generation for mode: $mode"
        fi
        echo "$password"
        return 0
    fi
    return 1
}

# Function to create new key using C helper
create_new_key() {
    local benchmark_start=""
    if [ "$BENCHMARK" = "true" ]; then
        benchmark_start=$(date +%s.%N)
    fi

    local program="$1"
    local username="$2"
    local password="$3"

    # Initialize ramdisk for temp files
    time_operation init_ramdisk || error_exit "Failed to initialize ramdisk"
    
    # Create temp input file for C helper
    local input_file="$TEMP_DIR/newkey_input.$$"
    printf 'service=%s\nusername=%s\npassword=%s\n' "$program" "$username" "$password" > "$input_file"
    
    # Call C helper to encrypt and store credentials
    /vault/keyman/keyman-crypto create "$input_file"
    local crypto_exit_code=$?
    
    # Securely cleanup temp file
    shred -u "$input_file" 2>/dev/null || rm -f "$input_file"
    
    # Clean up ramdisk
    time_operation secure_cleanup

    if [ "$BENCHMARK" = "true" ] && [ -n "$benchmark_start" ]; then
        benchmark_log "$benchmark_start" "Total create_new_key operation"
    fi
    
    if [ $crypto_exit_code -eq 0 ]; then
        echo "Successfully created key for $program"
        return 0
    else
        error_exit "Failed to create key for $program (exit code: $crypto_exit_code)"
        return $crypto_exit_code
    fi
}

# Main script logic
if [ $# -ne 3 ]; then
    error_exit "Usage: $0 <program_name> <username> <password>"
fi

program="$1"
username="$2"
password="$3"

# Sanitize the program name:  Allow only alphanumeric characters and underscores
if ! [[ "$program" =~ ^[a-zA-Z0-9_]+$ ]]; then
    error_exit "Invalid program name: $program"
fi

# No password validation needed - C helper handles any characters

create_new_key "$program" "$username" "$password"
