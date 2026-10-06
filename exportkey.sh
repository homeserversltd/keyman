#!/bin/bash
set +x

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh" || exit 1

SCOPED_EXPORT=false
if [ "${1:-}" = "--scoped" ]; then
    if [ "$#" -ne 2 ]; then
        printf 'MGLA REFUSAL: export-usage\n' >&2
        exit 2
    fi
    SCOPED_EXPORT=true
    KEYMAN_MGLA_SCOPED=1
    PROGRAM_NAME="$2"
elif [ "$#" -eq 1 ]; then
    PROGRAM_NAME="$1"
else
    error_exit "Usage: $0 <service_name>"
fi

if ! [[ "$PROGRAM_NAME" =~ ^[a-zA-Z0-9_]{1,238}$ ]]; then
    if [ "$SCOPED_EXPORT" = true ]; then
        printf 'MGLA REFUSAL: invalid-service-name\n' >&2
        exit 2
    fi
    error_exit "Invalid program name"
fi

check_key_system_initialized
ENCRYPTED_FILE="${VAULT_DIR}/${PROGRAM_NAME}.key"
OUTPUT_FILE="${TEMP_DIR}/${PROGRAM_NAME}"
INPUT_FILE=""
LEGACY_OUTPUT_FILE=""
OUTPUT_CREATED=false
OUTPUT_DEVICE=""
OUTPUT_INODE=""
SCRIPT_SUCCESS=false

if [ "$BENCHMARK" = "true" ]; then
    start_time=$(date +%s.%N)
fi

remove_owned_file() {
    local path="$1"
    if [ -e "$path" ] || [ -L "$path" ]; then
        if [ -L "$path" ] || [ ! -f "$path" ]; then
            return 1
        fi
        shred -u -- "$path" 2>/dev/null || rm -f -- "$path"
    fi
    [ ! -e "$path" ] && [ ! -L "$path" ]
}

cleanup_export() {
    [ "$SCOPED_EXPORT" = true ] || return 0
    [ "$OUTPUT_CREATED" = true ] || return 0
    if [ ! -e "$OUTPUT_FILE" ] && [ ! -L "$OUTPUT_FILE" ]; then
        OUTPUT_CREATED=false
        return 0
    fi
    if [ -L "$OUTPUT_FILE" ] || [ ! -f "$OUTPUT_FILE" ]; then
        return 1
    fi
    local identity
    identity=$(stat -c '%d %i' -- "$OUTPUT_FILE" 2>/dev/null) || return 1
    if [ "$identity" != "$OUTPUT_DEVICE $OUTPUT_INODE" ]; then
        return 1
    fi
    if ! remove_owned_file "$OUTPUT_FILE"; then
        return 1
    fi
    OUTPUT_CREATED=false
}

cleanup_operation() {
    local status=0
    if [ -n "$INPUT_FILE" ]; then
        remove_owned_file "$INPUT_FILE" || status=1
        INPUT_FILE=""
    fi
    if [ -n "$LEGACY_OUTPUT_FILE" ]; then
        remove_owned_file "$LEGACY_OUTPUT_FILE" || status=1
        LEGACY_OUTPUT_FILE=""
    fi
    if [ "$SCRIPT_SUCCESS" != true ]; then
        cleanup_export || status=1
    fi
    return "$status"
}

handle_signal() {
    local signal_name="$1"
    if ! cleanup_operation; then
        printf 'MGLA REFUSAL: export-cleanup-failed\n' >&2
        exit 1
    fi
    printf 'MGLA REFUSAL: interrupted-%s\n' "$signal_name" >&2
    exit 128
}
trap 'cleanup_operation || { printf "MGLA REFUSAL: export-cleanup-failed\\n" >&2; exit 1; }' EXIT
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

if [ "$SCOPED_EXPORT" = true ]; then
    if [ -e "$OUTPUT_FILE" ] || [ -L "$OUTPUT_FILE" ]; then
        printf 'MGLA REFUSAL: exchange-artifact-exists\n' >&2
        exit 1
    fi
    KEYMAN_MGLA_SCOPED=1 init_ramdisk || {
        printf 'MGLA REFUSAL: key-exchange-tmpfs-missing\n' >&2
        exit 1
    }
else
    time_operation init_ramdisk || error_exit "Failed to initialize ramdisk"
fi

umask 077
INPUT_FILE=$(mktemp --tmpdir="$TEMP_DIR" export_input.XXXXXXXX) || {
    if [ "$SCOPED_EXPORT" = true ]; then
        printf 'MGLA REFUSAL: plaintext-temp-create-failed\n' >&2
        exit 1
    fi
    error_exit "Failed to create temp input file"
}
printf 'service=%s\n' "$PROGRAM_NAME" > "$INPUT_FILE" || {
    if [ "$SCOPED_EXPORT" = true ]; then
        printf 'MGLA REFUSAL: plaintext-temp-write-failed\n' >&2
        exit 1
    fi
    error_exit "Failed to write temp input file"
}

if [ "$SCOPED_EXPORT" = true ]; then
    "$KEYMAN_DIR/keyman-crypto" decrypt-exclusive "$INPUT_FILE" "$OUTPUT_FILE"
else
    LEGACY_OUTPUT_FILE=$(mktemp --tmpdir="$TEMP_DIR" export_output.XXXXXXXX) || error_exit "Failed to create temp output file"
    "$KEYMAN_DIR/keyman-crypto" decrypt "$INPUT_FILE" "$LEGACY_OUTPUT_FILE"
fi
crypto_exit_code=$?
if ! remove_owned_file "$INPUT_FILE"; then
    printf 'MGLA REFUSAL: plaintext-temp-cleanup-failed\n' >&2
    exit 1
fi
INPUT_FILE=""

if [ "$crypto_exit_code" -ne 0 ]; then
    if [ "$SCOPED_EXPORT" = true ]; then
        printf 'MGLA REFUSAL: keyman-export-failed\n' >&2
        exit "$crypto_exit_code"
    fi
    error_exit "Failed to decrypt service key (exit code: $crypto_exit_code)"
fi

if [ "$SCOPED_EXPORT" = true ]; then
    OUTPUT_CREATED=true
    identity=$(stat -c '%d %i' -- "$OUTPUT_FILE" 2>/dev/null) || {
        printf 'MGLA REFUSAL: export-cleanup-failed\n' >&2
        exit 1
    }
    OUTPUT_DEVICE="${identity%% *}"
    OUTPUT_INODE="${identity##* }"
else
    mv -f -- "$LEGACY_OUTPUT_FILE" "$OUTPUT_FILE" || error_exit "Failed to publish decrypted export"
    LEGACY_OUTPUT_FILE=""
fi

if [ "$SCOPED_EXPORT" != true ]; then
    start_cleanup_timer
    extend_cleanup_timer
fi

if [ "$BENCHMARK" = "true" ] && [ -n "${start_time:-}" ]; then
    benchmark_log "$start_time" "Total key export operation"
fi

echo "Acquired key for $PROGRAM_NAME"
SCRIPT_SUCCESS=true
exit 0
