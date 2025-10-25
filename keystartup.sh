#!/bin/bash
#can delete the service_suite.key and run this script to default the service suite password to the master password
#can delete the skeleton.key and run this script to generate a new master password, but know that all existing keys will be lost
# Default root password - if empty, will use skeleton key
# Read from environment variable if set, otherwise empty
DEFAULT_ROOT_PASSWORD="${DEFAULT_ROOT_PASSWORD:-}"
# Check if we're running in automated mode
AUTOMATED_SETUP=${AUTOMATED_SETUP:-0}
# Source utility functions
source /vault/keyman/utils.sh

# Function to get the admin user
get_admin_user() {
echo "owner"
}

# Function to set admin user password
set_admin_password() {
    local password="$1"
    local admin_user=$(get_admin_user)
    echo "${admin_user}:$password" | chpasswd || error_exit "Failed to set admin user password"
    
    # Write password to ~/password.txt for reference
    echo "$password" > "/deploy/password.txt"
    chmod 777 "/deploy/password.txt"
    chown "${admin_user}:${admin_user}" "/deploy/password.txt"
    echo "Admin password written to /deploy/password.txt"
}

setup_key_system() {
    # Get admin user for ownership
    local admin_user=$(get_admin_user)
    
    # Create necessary directories with proper permissions and ownership
    mkdir -p "$KEY_DIR" || error_exit "Failed to create key directory"
    chmod 700 "$KEY_DIR"
    chown "${admin_user}:${admin_user}" "$KEY_DIR"
    
    mkdir -p "$VAULT_DIR" || error_exit "Failed to create vault directory"
    chmod 700 "$VAULT_DIR"
    
    # Handle skeleton.key setup (master password)
    if [ ! -f "$SKELETON_KEY" ]; then
        if [ "$AUTOMATED_SETUP" = "1" ]; then
            # Automated first-time setup
            MASTER_PASSWORD=$(generate_secure_password)
            while ! validate_password "$MASTER_PASSWORD"; do
                MASTER_PASSWORD=$(generate_secure_password)
            done
            echo "$MASTER_PASSWORD" > "$SKELETON_KEY"
            chmod 600 "$SKELETON_KEY"
            chown "${admin_user}:${admin_user}" "$SKELETON_KEY"

            # Set admin user password
            if [ -n "$DEFAULT_ROOT_PASSWORD" ] && [ "$TEST_FLAG" != "1" ]; then
                set_admin_password "$DEFAULT_ROOT_PASSWORD"
            elif [ "$TEST_FLAG" != "1" ]; then
                set_admin_password "$MASTER_PASSWORD"
            fi

            # Create service suite key (encryption key for all service credentials)
            init_ramdisk
            # Always use skeleton key as service suite password for consistent recovery
            SERVICE_SUITE_PASSWORD="$MASTER_PASSWORD"
            echo "username=\"service_suite\"" > "$TEMP_DIR/service_suite"
            echo "password=\"$SERVICE_SUITE_PASSWORD\"" >> "$TEMP_DIR/service_suite"
            
            # Encrypt service suite key with master password
            openssl enc -aes-256-cbc -pbkdf2 -salt -in "$TEMP_DIR/service_suite" \
                -out "$SERVICE_SUITE_KEY" -pass pass:"$MASTER_PASSWORD"
            chmod 600 "$SERVICE_SUITE_KEY"
            
            # Create NAS key (clone of service suite key for NAS encryption)
            echo "username=\"nas\"" > "$TEMP_DIR/nas"
            echo "password=\"$SERVICE_SUITE_PASSWORD\"" >> "$TEMP_DIR/nas"
            
            # Encrypt NAS key with master password
            openssl enc -aes-256-cbc -pbkdf2 -salt -in "$TEMP_DIR/nas" \
                -out "$NAS_KEY" -pass pass:"$MASTER_PASSWORD"
            chmod 600 "$NAS_KEY"
            
            unset SERVICE_SUITE_PASSWORD
            secure_cleanup
            
        else
            # Interactive recovery mode
            echo "Master password (skeleton.key) not found."
            if [ -f "$SERVICE_SUITE_KEY" ]; then
                echo -e "\nWARNING: service_suite.key exists but skeleton.key is missing."
                echo "If you know the original master password, you can restore it."
                echo "Otherwise, all existing encrypted service credentials will become inaccessible."
                
                read -p "Do you know the original master password? (y/N): " knows_password
                if [[ "$knows_password" =~ ^[Yy]$ ]]; then
                    read -s -p "Enter the original master password: " original_master
                    echo
                    
                    init_ramdisk
                    
                    # Verify master password by attempting to decrypt service suite key
                    if openssl enc -d -aes-256-cbc -pbkdf2 -in "$SERVICE_SUITE_KEY" \
                        -out "$TEMP_DIR/service_suite" -pass pass:"$original_master" 2>/dev/null; then
                        echo "$original_master" > "$SKELETON_KEY"
                        chmod 600 "$SKELETON_KEY"
                        echo "skeleton.key has been restored successfully."
                        secure_cleanup
                        return 0
                    else
                        secure_cleanup
                        echo "Invalid master password."
                        read -p "Proceed with generating new master password? This will reset all keys. (y/N): " proceed
                        if [[ ! "$proceed" =~ ^[Yy]$ ]]; then
                            error_exit "Operation cancelled by user."
                        fi
                    fi
                fi
            fi
            
            echo "Generating new master password..."
            MASTER_PASSWORD=$(generate_secure_password)
            while ! validate_password "$MASTER_PASSWORD"; do
                MASTER_PASSWORD=$(generate_secure_password)
            done
            echo "$MASTER_PASSWORD" > "$SKELETON_KEY"
            chmod 600 "$SKELETON_KEY"
            
            echo -e "\nYour new master password is:\n$MASTER_PASSWORD"
            echo -e "\nPLEASE STORE THIS PASSWORD SECURELY!"
            echo "This is the factory default password for your device."
            echo "It cannot be recovered if lost."
            echo "Write it down and store it in a safe safe place."

            # Set admin user password
            if [ -n "$DEFAULT_ROOT_PASSWORD" ] && [ "$TEST_FLAG" != "1" ]; then
                set_admin_password "$DEFAULT_ROOT_PASSWORD"
            elif [ "$TEST_FLAG" != "1" ]; then
                set_admin_password "$MASTER_PASSWORD"
            fi
            
            read -p "Press Enter after you have securely stored the master password..."
            
            # Create new service suite key
            if [ -f "$SERVICE_SUITE_KEY" ]; then
                echo -e "\nWARNING: Creating new service suite key..."
                echo "All existing service credentials will need to be recreated."
                rm -f "$SERVICE_SUITE_KEY"
            fi
            
            init_ramdisk
            SERVICE_SUITE_PASSWORD=$(generate_secure_password)
            while ! validate_password "$SERVICE_SUITE_PASSWORD"; do
                SERVICE_SUITE_PASSWORD=$(generate_secure_password)
            done
            echo "username=\"service_suite\"" > "$TEMP_DIR/service_suite"
            echo "password=\"$SERVICE_SUITE_PASSWORD\"" >> "$TEMP_DIR/service_suite"
            
            # Encrypt service suite key with master password
            openssl enc -aes-256-cbc -pbkdf2 -salt -in "$TEMP_DIR/service_suite" \
                -out "$SERVICE_SUITE_KEY" -pass pass:"$MASTER_PASSWORD"
            chmod 600 "$SERVICE_SUITE_KEY"
            
            unset SERVICE_SUITE_PASSWORD
            secure_cleanup
            
            echo "Service suite key has been created."
            echo "You can now create new service credentials."
            
            if [ "$(ls -A "$VAULT_DIR"/*.key 2>/dev/null)" ]; then
                echo -e "\nWARNING: You will need to recreate all service credentials"
                echo "as they are no longer accessible with the new encryption key."
            fi
        fi
    fi
    
    # Create service suite key if missing
    if [ ! -f "$SERVICE_SUITE_KEY" ]; then
        echo "Recreating service suite key using the skeleton key (FAC)..."
        MASTER_PASSWORD=$(cat "$SKELETON_KEY")
        
        init_ramdisk
        
        # Always use skeleton key as service suite password for consistent recovery
        SERVICE_SUITE_PASSWORD="$MASTER_PASSWORD"
        
        echo "username=\"service_suite\"" > "$TEMP_DIR/service_suite"
        echo "password=\"$SERVICE_SUITE_PASSWORD\"" >> "$TEMP_DIR/service_suite"
        
        # Encrypt service suite key with master password
        openssl enc -aes-256-cbc -pbkdf2 -salt -in "$TEMP_DIR/service_suite" \
            -out "$SERVICE_SUITE_KEY" -pass pass:"$MASTER_PASSWORD"
        chmod 600 "$SERVICE_SUITE_KEY"
        
        # Verify the key was created correctly
        echo "Verifying service suite key encryption..."
        if ! openssl enc -d -aes-256-cbc -pbkdf2 -in "$SERVICE_SUITE_KEY" \
            -out "$TEMP_DIR/service_suite_verify" -pass pass:"$MASTER_PASSWORD" 2>/dev/null; then
            echo "ERROR: Failed to verify service suite key encryption!"
            rm -f "$SERVICE_SUITE_KEY"
            secure_cleanup
            error_exit "Service suite key creation failed verification"
        fi
        
        # Clean up verification file
        rm -f "$TEMP_DIR/service_suite_verify"
        
        unset SERVICE_SUITE_PASSWORD
        secure_cleanup
        
        if [ "$AUTOMATED_SETUP" != "1" ]; then
            echo "Service suite key generated successfully using the factory access key (FAC)."
            echo "You can now create service credentials."
        fi
    fi
    
    return 0
}

# Main execution
setup_key_system
exit $? 