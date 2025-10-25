#!/bin/bash

#directory where the scripts are located
readonly KEYMAN_DIR="/vault/keyman/"
readonly KEY_DIR="/root/key"
#this is the randomly generated password that ships with every device
readonly SKELETON_KEY="/root/key/skeleton.key"
readonly VAULT_DIR="/vault/.keys"
readonly SERVICE_SUITE_KEY="$VAULT_DIR/service_suite.key"  # Renamed from admin.key
readonly NAS_KEY="$VAULT_DIR/nas.key"  # NAS encryption key
readonly TEMP_DIR="/mnt/keyexchange"
readonly LOG_FILE="/mnt/ramdisk/logs/keymanagement.log"
readonly TIMER_FILE="/mnt/ramdisk/keyman_timer.pid"
readonly TIMER_TIMESTAMP="/mnt/ramdisk/keyman_timer.ts"
readonly CLEANUP_DELAY=15  # Seconds before cleanup
readonly DEBUG=${DEBUG:-false}  # Set to true to enable debug output
readonly BENCHMARK=${BENCHMARK:-false}  # Set to true to enable timing
readonly BENCHMARK_LOG="/mnt/ramdisk/logs/benchmark.log"
readonly SYSTEM_AUTH_SERVICES=("ssh" "ttyd")  # Services that use system authentication

# Define unambiguous character sets
UPPERCASE="ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # Added I, O back in
LOWERCASE="abcdefghijklmnopqrstuvwxyz"    # Added l, o, p back in
NUMBERS="0123456789"                     # Added 0, 1 back in
SYMBOLS="-._~"                         # Used for auto-generated passwords (keyman-crypto supports all characters for user passwords)

generate_secure_password() {
    local length=16  # Strong password length
    local password=""
    
    # Ensure at least one character from each set, starting with a non-symbol
    password+="${UPPERCASE:$((RANDOM % ${#UPPERCASE})):1}"
    password+="${LOWERCASE:$((RANDOM % ${#LOWERCASE})):1}"
    password+="${NUMBERS:$((RANDOM % ${#NUMBERS})):1}"
    password+="${SYMBOLS:$((RANDOM % ${#SYMBOLS})):1}"
    
    # Fill the rest with random characters from all sets
    local all_chars="${UPPERCASE}${LOWERCASE}${NUMBERS}${SYMBOLS}"
    local remaining_length=$((length - 4))
    
    for ((i=0; i<remaining_length; i++)); do
        password+="${all_chars:$((RANDOM % ${#all_chars})):1}"
    done
    
    # Shuffle the password
    password=$(echo "$password" | fold -w1 | shuf | tr -d '\n')
    
    # Ensure the first character is not a symbol
    if [[ "$SYMBOLS" == *"${password:0:1}"* ]]; then
        password="${password:1}${password:0:1}"
    fi

    echo "$password"
}


# Function to generate a random key
generate_random_key() {
    if [ "$BENCHMARK" = "true" ]; then
        local gen_start=$(date +%s.%N)
    fi

    # Use the defined character sets
    local key=""
    
    # Ensure at least one character from each set, starting with a non-symbol
    key+="${UPPERCASE:$((RANDOM % ${#UPPERCASE})):1}"
    key+="${LOWERCASE:$((RANDOM % ${#LOWERCASE})):1}"
    key+="${NUMBERS:$((RANDOM % ${#NUMBERS})):1}"
    key+="${SYMBOLS:$((RANDOM % ${#SYMBOLS})):1}"
    
    # Fill the rest with random characters from all sets
    local all_chars="${UPPERCASE}${LOWERCASE}${NUMBERS}${SYMBOLS}"
    local length=32
    local remaining_length=$((length - 4))
    
    for ((i=0; i<remaining_length; i++)); do
        key+="${all_chars:$((RANDOM % ${#all_chars})):1}"
    done
    
    # Shuffle the key
    key=$(echo "$key" | fold -w1 | shuf | tr -d '\n')
    
    # Ensure the first character is not a symbol
    if [[ "$SYMBOLS" == *"${key:0:1}"* ]]; then
        key="${key:1}${key:0:1}"
    fi

    debug_log "Generated random key of length $length"

    if [ "$BENCHMARK" = "true" ] && [ -n "$gen_start" ]; then
        benchmark_log "$gen_start" "Random key generation"
    fi

    echo "$key"
}

# Utility functions for keymanagement suite

# Function to securely delete a file
secure_delete() {
    shred -u "$1"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to securely delete $1"
        exit 1
    fi
}

# Function to handle errors and exit
error_exit() {
    echo "ERROR: $1" >&2
    exit 1
}

# Function to log messages
log_message() {
    if [ "$DEBUG" = "true" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    fi
}

check_key_system_initialized() {
    local missing_keys=()
    
    if [ ! -f "$SKELETON_KEY" ]; then
        missing_keys+=("skeleton key ($SKELETON_KEY)")
    fi
    
    if [ ! -f "$SERVICE_SUITE_KEY" ]; then
        missing_keys+=("service suite key ($SERVICE_SUITE_KEY)")
    fi
    
    if [ ${#missing_keys[@]} -gt 0 ]; then
        echo "ERROR: Key system not initialized. Missing: ${missing_keys[*]}. Please run keystartup.sh manually as root to initialize the key system."
        exit 1
    fi
}

# Function to get decrypted admin key content
get_service_suite_key() {
    # First check if service suite key is already decrypted in ramdisk
    if mountpoint -q "$TEMP_DIR" && [ -f "$TEMP_DIR/service_suite" ]; then
        # Validate that the existing file is actually readable and contains valid data
        if grep -q '^password=' "$TEMP_DIR/service_suite" 2>/dev/null; then
            debug_log "Service suite key already decrypted in ramdisk"
            return 0
        else
            debug_log "Existing service suite file is corrupted, re-decrypting..."
            rm -f "$TEMP_DIR/service_suite" "$TEMP_DIR/service_suite.key"
        fi
    fi

    # Make sure ramdisk is ready
    init_ramdisk || return 1

    # Only copy service suite key if it's not already in ramdisk
    if [ ! -f "$TEMP_DIR/service_suite.key" ]; then
        debug_log "Copying service suite key to ramdisk"
        cp "$SERVICE_SUITE_KEY" "$TEMP_DIR/service_suite.key" || {
            error_exit "Failed to copy service suite key to ramdisk"
            return 1
        }
    fi
    
    # Only decrypt if we haven't already
    if [ ! -f "$TEMP_DIR/service_suite" ]; then
        debug_log "Decrypting service suite key"
        local master_password=$(cat "$SKELETON_KEY")
        
        if ! openssl enc -d -aes-256-cbc -pbkdf2 -in "$TEMP_DIR/service_suite.key" \
            -out "$TEMP_DIR/service_suite" -pass pass:"$master_password" 2>/dev/null; then
            unset master_password
            error_exit "Failed to decrypt service suite key"
            return 1
        fi
        
        unset master_password
    fi
    
    debug_log "Service suite key ready"
    return 0
}

# encrypt_files() function removed - obsolete (replaced by keyman-crypto.c)

# decrypt_files() function removed - obsolete (replaced by keyman-crypto.c)

#do not run this manually ; exportkey.sh handles this
secure_cleanup() {
    # Only proceed if the directory exists
    if [ -d "$TEMP_DIR" ]; then
        # Clean up files if any exist
        if [ "$(ls -A "$TEMP_DIR" 2>/dev/null)" ]; then
            for file in "$TEMP_DIR"/*; do
                if [ -f "$file" ]; then
                    shred -u "$file" 2>/dev/null || true
                fi
            done
        fi
        
        # Only try to unmount if it's actually mounted
        if mountpoint -q "$TEMP_DIR" 2>/dev/null; then
            umount "$TEMP_DIR" 2>/dev/null || true
        fi
        
        # Remove directory if it still exists
        rmdir "$TEMP_DIR" 2>/dev/null || true
    fi
}

# Function to initialize ramdisk
init_ramdisk() {
    # If ramdisk is already mounted and accessible, just use it
    if mountpoint -q "$TEMP_DIR" 2>/dev/null && [ -w "$TEMP_DIR" ]; then
        debug_log "Using existing RAM disk mount"
        return 0
    fi

    # Only clean up if mount exists but is not writable
    if mountpoint -q "$TEMP_DIR" 2>/dev/null; then
        debug_log "Cleaning up non-writable RAM disk mount..."
        secure_cleanup
    fi

    # Now create fresh mount point
    debug_log "Creating mount point at $TEMP_DIR"
    mkdir -p "$TEMP_DIR" || {
        error_exit "Failed to create RAM disk mount point"
        return 1
    }

    # Mount fresh ramdisk
    debug_log "Mounting fresh RAM disk at $TEMP_DIR"
    mount -t tmpfs -o size=100M,mode=700 tmpfs "$TEMP_DIR" || {
        error_exit "Failed to mount RAM disk"
        rmdir "$TEMP_DIR" 2>/dev/null
        return 1
    }

    # Double check mount and permissions
    if ! mountpoint -q "$TEMP_DIR"; then
        error_exit "RAM disk mount verification failed"
        rmdir "$TEMP_DIR" 2>/dev/null
        return 1
    fi

    # Ensure proper permissions
    chmod 700 "$TEMP_DIR" || {
        error_exit "Failed to set RAM disk permissions"
        umount "$TEMP_DIR" 2>/dev/null
        rmdir "$TEMP_DIR" 2>/dev/null
        return 1
    }

    debug_log "RAM disk successfully initialized at $TEMP_DIR"
    return 0
}

extend_cleanup_timer() {
    # Update or create timestamp file
    date +%s > "$TIMER_TIMESTAMP"
}

start_cleanup_timer() {
    # If there's an existing timer, don't start a new one
    if [ -f "$TIMER_FILE" ]; then
        old_pid=$(cat "$TIMER_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            # Timer already running, just extend it
            extend_cleanup_timer
            return 0
        fi
    fi

    # Start new timer process
    (
        # Store timer PID
        echo $$ > "$TIMER_FILE"
        extend_cleanup_timer
        
        while true; do
            sleep 2  # Check every 2 seconds
            
            if [ ! -f "$TIMER_TIMESTAMP" ]; then
                break
            fi
            
            # Get time elapsed since last extension
            last_time=$(cat "$TIMER_TIMESTAMP")
            current_time=$(date +%s)
            elapsed=$((current_time - last_time))
            
            # If no activity for CLEANUP_DELAY seconds, cleanup and exit
            if [ $elapsed -ge $CLEANUP_DELAY ]; then
                secure_cleanup
                rm -f "$TIMER_FILE" "$TIMER_TIMESTAMP"
                exit 0
            fi
        done
    ) &
}

# debug logging function
debug_log() {
    if [ "$DEBUG" = "true" ]; then
        echo "DEBUG: $1"
    fi
}

# Function to log benchmark timings
benchmark_log() {
    if [ "$BENCHMARK" = "true" ]; then
        local start_time=$1
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc)
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $2 took ${duration}s" >> "$BENCHMARK_LOG"
    fi
}

# Wrapper function to time operations
time_operation() {
    if [ "$BENCHMARK" = "true" ]; then
        local start_time=$(date +%s.%N)
        "$@"
        local status=$?
        benchmark_log "$start_time" "${FUNCNAME[1]}"
        return $status
    else
        "$@"
    fi
}

# Function to validate password format
# Updated for keyman-crypto compatibility - allows any characters
validate_password() {
    local password="$1"
    
    # With keyman-crypto, any characters are allowed
    # Only check that password is not empty
    if [ -z "$password" ]; then
        if [ "$DEBUG" = "true" ]; then
            echo "Password validation failed - empty password"
        fi
        return 1
    fi
    
    if [ "$DEBUG" = "true" ]; then
        echo "Password validation passed - keyman-crypto supports all characters (length: ${#password})"
    fi
    
    return 0
}

# Update validate_manual_password to use this function
validate_manual_password() {
    validate_password "$1"
}
