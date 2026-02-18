#!/bin/bash

# Source utility functions and paths
source /vault/keyman/utils.sh

# Non-interactive mode: delete a single key by service name (e.g. for backblazeTab bucket removal).
# Usage: deletekey.sh <service_name>
# service_name must contain only [a-zA-Z0-9_] (no path traversal, matches keyman keyfile naming).
if [ -n "$1" ]; then
    service_name="$1"
    if [[ ! "$service_name" =~ ^[a-zA-Z0-9_]+$ ]]; then
        echo "Error: Service name must contain only letters, numbers, and underscores." >&2
        exit 1
    fi
    key_file="${VAULT_DIR}/${service_name}.key"
    if [ ! -f "$key_file" ]; then
        echo "Error: Key file ${service_name}.key not found." >&2
        exit 1
    fi
    rm -f "$key_file"
    echo "Key file $(basename "$key_file") deleted."
    exit 0
fi

# Interactive mode: list keys and prompt for selection
list_key_files() {
    echo "Select the key file to delete:"
    local i=1
    for key_file in "$VAULT_DIR"/*.key; do
        key_files+=("$key_file")
        echo "[$i] $(basename "$key_file")"
        ((i++))
    done
}

prompt_key_file_selection() {
    local key_index
    while true; do
        read -p "Enter the number corresponding to the key file: " key_index
        if [[ "$key_index" =~ ^[0-9]+$ ]] && (( key_index >= 1 && key_index <= ${#key_files[@]} )); then
            local selected_key_file="${key_files[$((key_index - 1))]}"
            echo "$selected_key_file"
            break
        else
            echo "Error: Invalid selection. Please enter a valid number."
        fi
    done
}

list_key_files
selected_key_file=$(prompt_key_file_selection)

read -p "Are you sure you want to delete $(basename "$selected_key_file")? [y/N]: " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    rm -f "$selected_key_file"
    echo "Key file $(basename "$selected_key_file") deleted."
else
    echo "Deletion cancelled."
fi
