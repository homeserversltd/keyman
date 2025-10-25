#!/bin/bash

# Source utility functions and paths
source /vault/keyman/utils.sh
# Function to list available key files
list_key_files() {
    echo "Select the key file to delete:"
    local i=1
    for key_file in "$VAULT_DIR"/*.key; do
        key_files+=("$key_file")
        echo "[$i] $(basename "$key_file")"
        ((i++))
    done
}

# Function to prompt for key file selection
prompt_key_file_selection() {
    local key_index
    while true; do
        read -p "Enter the number corresponding to the key file: " key_index
        # Validate input
        if [[ "$key_index" =~ ^[0-9]+$ ]] && (( key_index >= 1 && key_index <= ${#key_files[@]} )); then
            local selected_key_file="${key_files[$((key_index - 1))]}"
            echo "$selected_key_file"
            break
        else
            echo "Error: Invalid selection. Please enter a valid number."
        fi
    done
}

# Main script logic
list_key_files
selected_key_file=$(prompt_key_file_selection)

# Confirm deletion
read -p "Are you sure you want to delete $(basename "$selected_key_file")? [y/N]: " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    secure_delete "$selected_key_file"
    echo "Key file $(basename "$selected_key_file") has been securely deleted."
else
    echo "Deletion cancelled."
fi
