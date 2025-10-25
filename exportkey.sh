#!/bin/bash

source /vault/keyman/utils.sh

# Check if key system is initialized
check_key_system_initialized

PROGRAM_NAME="$1"
ENCRYPTED_FILE="${VAULT_DIR}/${PROGRAM_NAME}.key"

if [ "$BENCHMARK" = "true" ]; then
    start_time=$(date +%s.%N)
fi

# Main export logic using C helper
main_export() {
    PROGRAM_NAME="$1"
    ENCRYPTED_FILE="${VAULT_DIR}/${PROGRAM_NAME}.key"

    # Check if the encrypted file exists first
    if [ ! -f "$ENCRYPTED_FILE" ]; then
        error_exit "Encrypted file ${ENCRYPTED_FILE} not found"
    fi

    # Initialize ramdisk for temp files
    time_operation init_ramdisk || error_exit "Failed to initialize ramdisk"

    # Create temp input file for C helper
    local input_file="$TEMP_DIR/export_input.$$"
    printf 'service=%s\n' "$PROGRAM_NAME" > "$input_file"
    
    # Create temp output file path
    local output_file="$TEMP_DIR/export_output.$$"
    
    # Call C helper for decryption
    /vault/keyman/keyman-crypto decrypt "$input_file" "$output_file"
    local crypto_exit_code=$?
    
    # Cleanup input file
    shred -u "$input_file" 2>/dev/null || rm -f "$input_file"
    
    if [ $crypto_exit_code -eq 0 ]; then
        # C helper succeeded, move decrypted file to expected location
        mv "$output_file" "$TEMP_DIR/$PROGRAM_NAME"
    else
        # Cleanup output file on failure
        shred -u "$output_file" 2>/dev/null || rm -f "$output_file"
        error_exit "Failed to decrypt service key (exit code: $crypto_exit_code)"
    fi
}

# Execute main export with benchmarking
time_operation main_export "$1"

# Start or extend cleanup timer
start_cleanup_timer
extend_cleanup_timer

if [ "$BENCHMARK" = "true" ] && [ -n "$start_time" ]; then
    benchmark_log "$start_time" "Total key export operation"
fi

echo "Acquired key for $PROGRAM_NAME"
exit 0

