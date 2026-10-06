#!/bin/bash
set +x

# Source the runtime-local utility functions; this also resolves KEYMAN_ROOT.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh" || exit 1

MGLA_INPUT_FILE=""
cleanup_mgla_input() {
    if [ -n "$MGLA_INPUT_FILE" ]; then
        if [ -e "$MGLA_INPUT_FILE" ] || [ -L "$MGLA_INPUT_FILE" ]; then
            if [ -L "$MGLA_INPUT_FILE" ] || [ ! -f "$MGLA_INPUT_FILE" ]; then
                return 1
            fi
            shred -u -- "$MGLA_INPUT_FILE" 2>/dev/null || rm -f -- "$MGLA_INPUT_FILE"
        fi
        if [ -e "$MGLA_INPUT_FILE" ] || [ -L "$MGLA_INPUT_FILE" ]; then
            return 1
        fi
        MGLA_INPUT_FILE=""
    fi
    unset username password extra
    return 0
}

handle_mgla_signal() {
    local signal_name="$1"
    if ! cleanup_mgla_input; then
        printf 'MGLA REFUSAL: plaintext-temp-cleanup-failed\n' >&2
        exit 1
    fi
    printf 'MGLA REFUSAL: interrupted-%s\n' "$signal_name" >&2
    exit 128
}

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
    local exclusive="${4:-false}"
    local input_file=""
    local crypto_exit_code=0

    if [ "$exclusive" = "true" ]; then
        KEYMAN_MGLA_SCOPED=1 init_ramdisk || {
            printf 'MGLA REFUSAL: key-exchange-tmpfs-missing\n' >&2
            unset username password
            return 1
        }
        umask 077
        input_file=$(mktemp --tmpdir="$TEMP_DIR" newkey_input.XXXXXXXX) || {
            printf 'MGLA REFUSAL: plaintext-temp-create-failed\n' >&2
            unset username password
            return 1
        }
        MGLA_INPUT_FILE="$input_file"
        chmod 600 "$input_file" || {
            if ! cleanup_mgla_input; then
                printf 'MGLA REFUSAL: plaintext-temp-cleanup-failed\n' >&2
                return 1
            fi
            printf 'MGLA REFUSAL: plaintext-temp-create-failed\n' >&2
            return 1
        }
        if ! printf 'service=%s\nusername=%s\npassword=%s\n' "$program" "$username" "$password" > "$input_file"; then
            if ! cleanup_mgla_input; then
                printf 'MGLA REFUSAL: plaintext-temp-cleanup-failed\n' >&2
                return 1
            fi
            printf 'MGLA REFUSAL: plaintext-temp-write-failed\n' >&2
            return 1
        fi
        "$KEYMAN_DIR/keyman-crypto" create-exclusive "$input_file"
        crypto_exit_code=$?
        cleanup_mgla_input || {
            printf 'MGLA REFUSAL: plaintext-temp-cleanup-failed\n' >&2
            return 1
        }
        if [ "$crypto_exit_code" -ne 0 ]; then
            printf 'MGLA REFUSAL: keyman-newkey-failed\n' >&2
            return "$crypto_exit_code"
        fi
        echo "Successfully created key for $program"
        return 0
    fi

    time_operation init_ramdisk || error_exit "Failed to initialize ramdisk"
    umask 077
    input_file=$(mktemp --tmpdir="$TEMP_DIR" newkey_input.XXXXXXXX) || error_exit "Failed to create temp input file"
    printf 'service=%s\nusername=%s\npassword=%s\n' "$program" "$username" "$password" > "$input_file" || error_exit "Failed to write temp input file"
    "$KEYMAN_DIR/keyman-crypto" create "$input_file"
    crypto_exit_code=$?
    unset username password
    shred -u -- "$input_file" 2>/dev/null || rm -f -- "$input_file"
    time_operation secure_cleanup

    if [ "$BENCHMARK" = "true" ] && [ -n "$benchmark_start" ]; then
        benchmark_log "$benchmark_start" "Total create_new_key operation"
    fi

    if [ "$crypto_exit_code" -eq 0 ]; then
        echo "Successfully created key for $program"
        return 0
    else
        error_exit "Failed to create key for $program (exit code: $crypto_exit_code)"
        return "$crypto_exit_code"
    fi
}

# Main script logic. MGLA uses stdin only for the credential secret; the legacy
# three-argument invocation remains source-compatible.
internal_stdin=false
exclusive=false
if [ "${1:-}" = "--stdin" ]; then
    unset username password extra
    if [ "$#" -ne 2 ]; then
        printf 'MGLA REFUSAL: newkey-stdin-usage\n' >&2
        exit 2
    fi
    internal_stdin=true
    exclusive=true
    trap 'handle_mgla_signal INT' INT
    trap 'handle_mgla_signal TERM' TERM
    program="$2"
    if ! IFS= read -r username || ! IFS= read -r password; then
        printf 'MGLA REFUSAL: newkey-stdin-input-invalid\n' >&2
        exit 2
    fi
    if IFS= read -r extra || [ -n "${extra:-}" ]; then
        unset username password extra
        printf 'MGLA REFUSAL: newkey-stdin-input-invalid\n' >&2
        exit 2
    fi
    if [ "$username" != "mgla" ] || ! [[ "$password" =~ ^[0-9a-f]{64}$ ]]; then
        unset username password
        printf 'MGLA REFUSAL: newkey-stdin-input-invalid\n' >&2
        exit 2
    fi
else
    if [ "$#" -ne 3 ]; then
        error_exit "Usage: $0 <program_name> <username> <password>"
    fi
    program="$1"
    username="$2"
    password="$3"
fi

# The C credential record and output path are bounded; service names must also
# match Rust's MAX_SERVICE_NAME to keep the shell, C, and released CLI aligned.
if ! [[ "$program" =~ ^[a-zA-Z0-9_]{1,238}$ ]]; then
    if [ "$internal_stdin" = true ]; then
        unset username password
        printf 'MGLA REFUSAL: invalid-service-name\n' >&2
        exit 2
    fi
    error_exit "Invalid program name"
fi

if [ "$exclusive" = true ] && { [ -e "$VAULT_DIR/${program}.key" ] || [ -L "$VAULT_DIR/${program}.key" ]; }; then
    unset username password
    printf 'MGLA REFUSAL: credential-exists-overwrite-refused\n' >&2
    exit 1
fi

create_new_key "$program" "$username" "$password" "$exclusive"
result=$?
unset username password extra
exit "$result"
