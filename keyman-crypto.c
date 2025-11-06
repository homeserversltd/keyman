#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/stat.h>

#define MAX_LINE_LENGTH 1024
#define MAX_PASSWORD_LENGTH 512
#define SALT_SIZE 8
#define IV_SIZE 16

// Exit codes
#define EXIT_SUCCESS 0
#define EXIT_CRYPTO_ERROR 1
#define EXIT_IO_ERROR 2
#define EXIT_INPUT_ERROR 3
#define EXIT_USAGE_ERROR 4

// Secure memory cleanup
void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

// Read skeleton key
int read_skeleton_key(char *key_buffer, size_t buffer_size) {
    FILE *fp = fopen("/root/key/skeleton.key", "r");
    if (!fp) {
        fprintf(stderr, "ERROR: Cannot read skeleton key\n");
        return EXIT_IO_ERROR;
    }
    
    if (!fgets(key_buffer, buffer_size, fp)) {
        fclose(fp);
        fprintf(stderr, "ERROR: Cannot read skeleton key content\n");
        return EXIT_IO_ERROR;
    }
    
    fclose(fp);
    
    // Remove newline if present
    size_t len = strlen(key_buffer);
    if (len > 0 && key_buffer[len-1] == '\n') {
        key_buffer[len-1] = '\0';
    }
    
    return EXIT_SUCCESS;
}

// Read service suite key and decrypt it
int get_service_suite_password(char *password_buffer, size_t buffer_size) {
    char skeleton_key[MAX_PASSWORD_LENGTH];
    if (read_skeleton_key(skeleton_key, sizeof(skeleton_key)) != EXIT_SUCCESS) {
        return EXIT_IO_ERROR;
    }
    
    FILE *fp = fopen("/vault/.keys/service_suite.key", "rb");
    if (!fp) {
        secure_zero(skeleton_key, sizeof(skeleton_key));
        fprintf(stderr, "ERROR: Cannot read service suite key\n");
        return EXIT_IO_ERROR;
    }
    
    // Read encrypted service suite key
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    unsigned char *encrypted_data = malloc(file_size);
    if (!encrypted_data) {
        fclose(fp);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_IO_ERROR;
    }
    
    fread(encrypted_data, 1, file_size, fp);
    fclose(fp);
    
    // Decrypt using OpenSSL EVP interface (PBKDF2 + AES-256-CBC)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_data);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_CRYPTO_ERROR;
    }
    
    // Extract salt from encrypted data (first 8 bytes after "Salted__")
    if (file_size < 16 || memcmp(encrypted_data, "Salted__", 8) != 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        fprintf(stderr, "ERROR: Invalid encrypted file format\n");
        return EXIT_CRYPTO_ERROR;
    }
    
    unsigned char salt[SALT_SIZE];
    memcpy(salt, encrypted_data + 8, SALT_SIZE);
    
    // Derive key and IV using PBKDF2 (48 bytes total: 32 for key + 16 for IV)
    unsigned char key_iv[48];
    if (PKCS5_PBKDF2_HMAC(skeleton_key, strlen(skeleton_key), salt, SALT_SIZE, 10000, EVP_sha256(), 48, key_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_CRYPTO_ERROR;
    }
    unsigned char *key = key_iv;
    unsigned char *iv = key_iv + 32;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_CRYPTO_ERROR;
    }
    
    // Decrypt
    unsigned char *plaintext = malloc(file_size);
    int len, plaintext_len;
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data + 16, file_size - 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        free(plaintext);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_CRYPTO_ERROR;
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        free(plaintext);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_CRYPTO_ERROR;
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    free(encrypted_data);
    secure_zero(skeleton_key, sizeof(skeleton_key));
    
    // Extract password from decrypted content
    plaintext[plaintext_len] = '\0';
    char *password_line = strstr((char*)plaintext, "password=");
    if (!password_line) {
        free(plaintext);
        fprintf(stderr, "ERROR: Cannot find password in service suite key\n");
        return EXIT_CRYPTO_ERROR;
    }
    
    // Extract password value (between quotes)
    char *start = strchr(password_line, '"');
    if (!start) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    start++;
    
    char *end = strchr(start, '"');
    if (!end) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    
    size_t password_len = end - start;
    if (password_len >= buffer_size) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    
    strncpy(password_buffer, start, password_len);
    password_buffer[password_len] = '\0';
    
    free(plaintext);
    return EXIT_SUCCESS;
}

// Encrypt service credentials
int encrypt_service_credentials(const char *service, const char *username, const char *password) {
    char service_suite_password[MAX_PASSWORD_LENGTH];
    if (get_service_suite_password(service_suite_password, sizeof(service_suite_password)) != EXIT_SUCCESS) {
        return EXIT_CRYPTO_ERROR;
    }
    
    // Create credentials content
    char credentials[MAX_LINE_LENGTH];
    snprintf(credentials, sizeof(credentials), "username=\"%s\"\npassword=\"%s\"\n", username, password);
    
    // Generate salt and IV
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        secure_zero(service_suite_password, sizeof(service_suite_password));
        return EXIT_CRYPTO_ERROR;
    }
    
    // Derive key and IV (48 bytes total: 32 for key + 16 for IV)
    unsigned char key_iv[48];
    if (PKCS5_PBKDF2_HMAC(service_suite_password, strlen(service_suite_password), salt, SALT_SIZE, 10000, EVP_sha256(), 48, key_iv) != 1) {
        secure_zero(service_suite_password, sizeof(service_suite_password));
        return EXIT_CRYPTO_ERROR;
    }
    unsigned char *key = key_iv;
    unsigned char *iv = key_iv + 32;
    
    secure_zero(service_suite_password, sizeof(service_suite_password));
    
    // Encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return EXIT_CRYPTO_ERROR;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_CRYPTO_ERROR;
    }
    
    int len, ciphertext_len;
    unsigned char *ciphertext = malloc(strlen(credentials) + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)credentials, strlen(credentials)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return EXIT_CRYPTO_ERROR;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return EXIT_CRYPTO_ERROR;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Write encrypted file
    char output_path[256];
    snprintf(output_path, sizeof(output_path), "/vault/.keys/%s.key", service);
    
    FILE *fp = fopen(output_path, "wb");
    if (!fp) {
        free(ciphertext);
        return EXIT_IO_ERROR;
    }
    
    // Write OpenSSL format: "Salted__" + salt + encrypted data
    fwrite("Salted__", 1, 8, fp);
    fwrite(salt, 1, SALT_SIZE, fp);
    fwrite(ciphertext, 1, ciphertext_len, fp);
    
    fclose(fp);
    free(ciphertext);
    
    return EXIT_SUCCESS;
}

// Re-encrypt service credentials with new service suite password
int reencrypt_service_credentials(const char *service, const char *new_suite_password) {
    char old_suite_password[MAX_PASSWORD_LENGTH];
    if (get_service_suite_password(old_suite_password, sizeof(old_suite_password)) != EXIT_SUCCESS) {
        return EXIT_CRYPTO_ERROR;
    }
    
    // Read encrypted service key
    char input_path[256];
    snprintf(input_path, sizeof(input_path), "/vault/.keys/%s.key", service);
    
    FILE *fp = fopen(input_path, "rb");
    if (!fp) {
        secure_zero(old_suite_password, sizeof(old_suite_password));
        fprintf(stderr, "ERROR: Service key file not found: %s\n", input_path);
        return EXIT_IO_ERROR;
    }
    
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    unsigned char *encrypted_data = malloc(file_size);
    fread(encrypted_data, 1, file_size, fp);
    fclose(fp);
    
    // Verify format and extract salt
    if (file_size < 16 || memcmp(encrypted_data, "Salted__", 8) != 0) {
        free(encrypted_data);
        secure_zero(old_suite_password, sizeof(old_suite_password));
        return EXIT_CRYPTO_ERROR;
    }
    
    unsigned char salt[SALT_SIZE];
    memcpy(salt, encrypted_data + 8, SALT_SIZE);
    
    // Derive key and IV using old password (48 bytes total: 32 for key + 16 for IV)
    unsigned char key_iv[48];
    PKCS5_PBKDF2_HMAC(old_suite_password, strlen(old_suite_password), salt, SALT_SIZE, 10000, EVP_sha256(), 48, key_iv);
    unsigned char *key = key_iv;
    unsigned char *iv = key_iv + 32;
    
    secure_zero(old_suite_password, sizeof(old_suite_password));
    
    // Decrypt with old password
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_data);
        return EXIT_CRYPTO_ERROR;
    }
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    unsigned char *plaintext = malloc(file_size);
    int len, plaintext_len;
    
    EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data + 16, file_size - 16);
    plaintext_len = len;
    
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    free(encrypted_data);
    
    // Extract username and password from decrypted content
    plaintext[plaintext_len] = '\0';
    char *username_line = strstr((char*)plaintext, "username=");
    char *password_line = strstr((char*)plaintext, "password=");
    
    if (!username_line || !password_line) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    
    // Extract username value (between quotes)
    char *username_start = strchr(username_line, '"');
    if (!username_start) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    username_start++;
    
    char *username_end = strchr(username_start, '"');
    if (!username_end) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    
    char username[MAX_PASSWORD_LENGTH];
    size_t username_len = username_end - username_start;
    if (username_len >= sizeof(username)) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    strncpy(username, username_start, username_len);
    username[username_len] = '\0';
    
    // Extract password value (between quotes)
    char *password_start = strchr(password_line, '"');
    if (!password_start) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    password_start++;
    
    char *password_end = strchr(password_start, '"');
    if (!password_end) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    
    char password[MAX_PASSWORD_LENGTH];
    size_t password_len = password_end - password_start;
    if (password_len >= sizeof(password)) {
        free(plaintext);
        return EXIT_CRYPTO_ERROR;
    }
    strncpy(password, password_start, password_len);
    password[password_len] = '\0';
    
    free(plaintext);
    
    // Now re-encrypt with new service suite password
    char credentials[MAX_LINE_LENGTH];
    snprintf(credentials, sizeof(credentials), "username=\"%s\"\npassword=\"%s\"\n", username, password);
    
    // Clear sensitive data
    secure_zero(username, sizeof(username));
    secure_zero(password, sizeof(password));
    
    // Generate new salt and IV
    unsigned char new_salt[SALT_SIZE];
    if (RAND_bytes(new_salt, SALT_SIZE) != 1) {
        return EXIT_CRYPTO_ERROR;
    }
    
    // Derive key and IV with new password (48 bytes total: 32 for key + 16 for IV)
    unsigned char new_key_iv[48];
    if (PKCS5_PBKDF2_HMAC(new_suite_password, strlen(new_suite_password), new_salt, SALT_SIZE, 10000, EVP_sha256(), 48, new_key_iv) != 1) {
        return EXIT_CRYPTO_ERROR;
    }
    unsigned char *new_key = new_key_iv;
    unsigned char *new_iv = new_key_iv + 32;
    
    // Encrypt with new password
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return EXIT_CRYPTO_ERROR;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, new_key, new_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_CRYPTO_ERROR;
    }
    
    unsigned char *ciphertext = malloc(strlen(credentials) + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int ciphertext_len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)credentials, strlen(credentials)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return EXIT_CRYPTO_ERROR;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return EXIT_CRYPTO_ERROR;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Write re-encrypted file
    char output_path[256];
    snprintf(output_path, sizeof(output_path), "/vault/.keys/%s.key", service);
    
    fp = fopen(output_path, "wb");
    if (!fp) {
        free(ciphertext);
        return EXIT_IO_ERROR;
    }
    
    // Write OpenSSL format: "Salted__" + salt + encrypted data
    fwrite("Salted__", 1, 8, fp);
    fwrite(new_salt, 1, SALT_SIZE, fp);
    fwrite(ciphertext, 1, ciphertext_len, fp);
    
    fclose(fp);
    free(ciphertext);
    
    return EXIT_SUCCESS;
}

// Decrypt service credentials
int decrypt_service_credentials(const char *service, const char *output_file) {
    // Special case: service_suite is encrypted with skeleton key, not service suite password
    if (strcmp(service, "service_suite") == 0) {
        char skeleton_key[MAX_PASSWORD_LENGTH];
        if (read_skeleton_key(skeleton_key, sizeof(skeleton_key)) != EXIT_SUCCESS) {
            return EXIT_IO_ERROR;
        }
        
        FILE *fp = fopen("/vault/.keys/service_suite.key", "rb");
        if (!fp) {
            secure_zero(skeleton_key, sizeof(skeleton_key));
            fprintf(stderr, "ERROR: Cannot read service suite key\n");
            return EXIT_IO_ERROR;
        }
        
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        
        unsigned char *encrypted_data = malloc(file_size);
        fread(encrypted_data, 1, file_size, fp);
        fclose(fp);
        
        // Verify format and extract salt
        if (file_size < 16 || memcmp(encrypted_data, "Salted__", 8) != 0) {
            free(encrypted_data);
            secure_zero(skeleton_key, sizeof(skeleton_key));
            return EXIT_CRYPTO_ERROR;
        }
        
        unsigned char salt[SALT_SIZE];
        memcpy(salt, encrypted_data + 8, SALT_SIZE);
        
        // Derive key and IV using skeleton key (48 bytes total: 32 for key + 16 for IV)
        unsigned char key_iv[48];
        PKCS5_PBKDF2_HMAC(skeleton_key, strlen(skeleton_key), salt, SALT_SIZE, 10000, EVP_sha256(), 48, key_iv);
        unsigned char *key = key_iv;
        unsigned char *iv = key_iv + 32;
        
        secure_zero(skeleton_key, sizeof(skeleton_key));
        
        // Decrypt
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            free(encrypted_data);
            return EXIT_CRYPTO_ERROR;
        }
        
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        
        unsigned char *plaintext = malloc(file_size);
        int len, plaintext_len;
        
        EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data + 16, file_size - 16);
        plaintext_len = len;
        
        EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        
        // Write decrypted credentials to output file
        fp = fopen(output_file, "w");
        if (!fp) {
            free(plaintext);
            return EXIT_IO_ERROR;
        }
        
        fwrite(plaintext, 1, plaintext_len, fp);
        fclose(fp);
        free(plaintext);
        
        return EXIT_SUCCESS;
    }
    
    // Normal service key decryption using service suite password
    char service_suite_password[MAX_PASSWORD_LENGTH];
    if (get_service_suite_password(service_suite_password, sizeof(service_suite_password)) != EXIT_SUCCESS) {
        return EXIT_CRYPTO_ERROR;
    }
    
    // Read encrypted service key
    char input_path[256];
    snprintf(input_path, sizeof(input_path), "/vault/.keys/%s.key", service);
    
    FILE *fp = fopen(input_path, "rb");
    if (!fp) {
        secure_zero(service_suite_password, sizeof(service_suite_password));
        fprintf(stderr, "ERROR: Service key file not found: %s\n", input_path);
        return EXIT_IO_ERROR;
    }
    
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    unsigned char *encrypted_data = malloc(file_size);
    fread(encrypted_data, 1, file_size, fp);
    fclose(fp);
    
    // Verify format and extract salt
    if (file_size < 16 || memcmp(encrypted_data, "Salted__", 8) != 0) {
        free(encrypted_data);
        secure_zero(service_suite_password, sizeof(service_suite_password));
        return EXIT_CRYPTO_ERROR;
    }
    
    unsigned char salt[SALT_SIZE];
    memcpy(salt, encrypted_data + 8, SALT_SIZE);
    
    // Derive key and IV (48 bytes total: 32 for key + 16 for IV)
    unsigned char key_iv[48];
    PKCS5_PBKDF2_HMAC(service_suite_password, strlen(service_suite_password), salt, SALT_SIZE, 10000, EVP_sha256(), 48, key_iv);
    unsigned char *key = key_iv;
    unsigned char *iv = key_iv + 32;
    
    secure_zero(service_suite_password, sizeof(service_suite_password));
    
    // Decrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_data);
        return EXIT_CRYPTO_ERROR;
    }
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    unsigned char *plaintext = malloc(file_size);
    int len, plaintext_len;
    
    EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data + 16, file_size - 16);
    plaintext_len = len;
    
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    free(encrypted_data);
    
    // Write decrypted credentials to output file
    fp = fopen(output_file, "w");
    if (!fp) {
        free(plaintext);
        return EXIT_IO_ERROR;
    }
    
    fwrite(plaintext, 1, plaintext_len, fp);
    fclose(fp);
    free(plaintext);
    
    return EXIT_SUCCESS;
}

// Encrypt service suite key with master password
int encrypt_suite_key(const char *input_file) {
    char skeleton_key[MAX_PASSWORD_LENGTH];
    if (read_skeleton_key(skeleton_key, sizeof(skeleton_key)) != EXIT_SUCCESS) {
        return EXIT_IO_ERROR;
    }
    
    // Read service suite content from input file
    FILE *fp = fopen(input_file, "r");
    if (!fp) {
        secure_zero(skeleton_key, sizeof(skeleton_key));
        fprintf(stderr, "ERROR: Cannot read service suite content file: %s\n", input_file);
        return EXIT_IO_ERROR;
    }
    
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc(file_size + 1);
    if (!content) {
        fclose(fp);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_IO_ERROR;
    }
    
    fread(content, 1, file_size, fp);
    content[file_size] = '\0';
    fclose(fp);
    
    // Generate salt and IV
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        free(content);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_CRYPTO_ERROR;
    }
    
    // Derive key and IV (48 bytes total: 32 for key + 16 for IV)
    unsigned char key_iv[48];
    if (PKCS5_PBKDF2_HMAC(skeleton_key, strlen(skeleton_key), salt, SALT_SIZE, 10000, EVP_sha256(), 48, key_iv) != 1) {
        free(content);
        secure_zero(skeleton_key, sizeof(skeleton_key));
        return EXIT_CRYPTO_ERROR;
    }
    unsigned char *key = key_iv;
    unsigned char *iv = key_iv + 32;
    
    secure_zero(skeleton_key, sizeof(skeleton_key));
    
    // Encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(content);
        return EXIT_CRYPTO_ERROR;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(content);
        return EXIT_CRYPTO_ERROR;
    }
    
    int len, ciphertext_len;
    unsigned char *ciphertext = malloc(strlen(content) + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)content, strlen(content)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(content);
        free(ciphertext);
        return EXIT_CRYPTO_ERROR;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(content);
        free(ciphertext);
        return EXIT_CRYPTO_ERROR;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    free(content);
    
    // Write encrypted service suite key
    fp = fopen("/vault/.keys/service_suite.key", "wb");
    if (!fp) {
        free(ciphertext);
        return EXIT_IO_ERROR;
    }
    
    // Write OpenSSL format: "Salted__" + salt + encrypted data
    fwrite("Salted__", 1, 8, fp);
    fwrite(salt, 1, SALT_SIZE, fp);
    fwrite(ciphertext, 1, ciphertext_len, fp);
    
    fclose(fp);
    free(ciphertext);
    
    return EXIT_SUCCESS;
}

// Parse input file for create operation
int parse_create_input(const char *input_file, char *service, char *username, char *password) {
    FILE *fp = fopen(input_file, "r");
    if (!fp) {
        return EXIT_IO_ERROR;
    }
    
    char line[MAX_LINE_LENGTH];
    int found_service = 0, found_username = 0, found_password = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        if (strncmp(line, "service=", 8) == 0) {
            strcpy(service, line + 8);
            found_service = 1;
        } else if (strncmp(line, "username=", 9) == 0) {
            strcpy(username, line + 9);
            found_username = 1;
        } else if (strncmp(line, "password=", 9) == 0) {
            strcpy(password, line + 9);
            found_password = 1;
        }
    }
    
    fclose(fp);
    
    if (!found_service || !found_username || !found_password) {
        return EXIT_INPUT_ERROR;
    }
    
    return EXIT_SUCCESS;
}

// Parse input file for decrypt operation
int parse_decrypt_input(const char *input_file, char *service) {
    FILE *fp = fopen(input_file, "r");
    if (!fp) {
        return EXIT_IO_ERROR;
    }
    
    char line[MAX_LINE_LENGTH];
    int found_service = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        if (strncmp(line, "service=", 8) == 0) {
            strcpy(service, line + 8);
            found_service = 1;
            break;
        }
    }
    
    fclose(fp);
    
    if (!found_service) {
        return EXIT_INPUT_ERROR;
    }
    
    return EXIT_SUCCESS;
}

// Parse input file for reencrypt operation
int parse_reencrypt_input(const char *input_file, char *service, char *new_password) {
    FILE *fp = fopen(input_file, "r");
    if (!fp) {
        return EXIT_IO_ERROR;
    }
    
    char line[MAX_LINE_LENGTH];
    int found_service = 0, found_password = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        if (strncmp(line, "service=", 8) == 0) {
            strcpy(service, line + 8);
            found_service = 1;
        } else if (strncmp(line, "new_password=", 13) == 0) {
            strcpy(new_password, line + 13);
            found_password = 1;
        }
    }
    
    fclose(fp);
    
    if (!found_service || !found_password) {
        return EXIT_INPUT_ERROR;
    }
    
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <create|decrypt|reencrypt|encrypt_suite_key> <input_file> [output_file]\n", argv[0]);
        return EXIT_USAGE_ERROR;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    if (strcmp(argv[1], "create") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s create <input_file>\n", argv[0]);
            return EXIT_USAGE_ERROR;
        }
        
        char service[256], username[MAX_PASSWORD_LENGTH], password[MAX_PASSWORD_LENGTH];
        
        int result = parse_create_input(argv[2], service, username, password);
        if (result != EXIT_SUCCESS) {
            return result;
        }
        
        result = encrypt_service_credentials(service, username, password);
        
        // Clear sensitive data
        secure_zero(username, sizeof(username));
        secure_zero(password, sizeof(password));
        
        return result;
        
    } else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s decrypt <input_file> <output_file>\n", argv[0]);
            return EXIT_USAGE_ERROR;
        }
        
        char service[256];
        
        int result = parse_decrypt_input(argv[2], service);
        if (result != EXIT_SUCCESS) {
            return result;
        }
        
        return decrypt_service_credentials(service, argv[3]);
        
    } else if (strcmp(argv[1], "reencrypt") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s reencrypt <input_file>\n", argv[0]);
            return EXIT_USAGE_ERROR;
        }
        
        char service[256], new_password[MAX_PASSWORD_LENGTH];
        
        int result = parse_reencrypt_input(argv[2], service, new_password);
        if (result != EXIT_SUCCESS) {
            return result;
        }
        
        result = reencrypt_service_credentials(service, new_password);
        
        // Clear sensitive data
        secure_zero(new_password, sizeof(new_password));
        
        return result;
        
    } else if (strcmp(argv[1], "encrypt_suite_key") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s encrypt_suite_key <input_file>\n", argv[0]);
            return EXIT_USAGE_ERROR;
        }
        
        return encrypt_suite_key(argv[2]);
        
    } else {
        fprintf(stderr, "ERROR: Unknown operation: %s\n", argv[1]);
        return EXIT_USAGE_ERROR;
    }
}
