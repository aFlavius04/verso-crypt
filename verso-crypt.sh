#!/bin/bash
# --- Strict Mode & Secure Defaults ---
set -euo pipefail # Exit on error, undefined variable, or pipe failure.
IFS=$'\n\t'       # Set Internal Field Separator to prevent word splitting.
umask 077         # Create new files with permissions 600 (owner read/write only).

# --- Global Configuration ---
# Array to track all temporary files and directories for cleanup.
declare -a TEMP_FILES=()
# Secure temporary directory path will be stored here.
SECURE_TMPDIR=""
# Debug mode (enable with `DEBUG=1 ./verso-crypt.sh ...`)
readonly DEBUG=${DEBUG:-0}

# --- Colors for User Interface ---
readonly RED='\e[38;5;196m'
readonly GREEN='\e[92m'
readonly YELLOW='\e[93m'
readonly CYAN='\e[96m'
readonly BLUE='\e[94m'
readonly RESET='\e[0m'

# --- Script Constants ---
readonly SCRIPT_NAME="$(basename "$0")"
readonly AES_KEY_SIZE=32  # 256 bits for AES key
readonly HMAC_KEY_SIZE=32 # 256 bits for HMAC-SHA256 key
readonly IV_SIZE=16       # 128 bits for AES-CBC IV

# ==============================================================================
# CORE UTILITY FUNCTIONS
# ==============================================================================

# --- Final Cleanup ---
# This function is called on EXIT, INT, or TERM signals to securely delete all temporary files.
cleanup() {
    local exit_code=$?
    # Only perform cleanup if the temp directory was successfully created.
    if [[ -n "$SECURE_TMPDIR" && -d "$SECURE_TMPDIR" ]]; then
        # Don't show cleanup message if not in debug mode. Keep the output clean.
        (( DEBUG )) && echo -e "${YELLOW}INFO: Cleaning up secure temporary directory: $SECURE_TMPDIR${RESET}" >&2
        rm -rf "$SECURE_TMPDIR"
    fi
    # Exit with the original exit code
    exit $exit_code
}
# Register the cleanup function to be called on script exit
trap cleanup EXIT INT TERM

# --- Error Handling ---
# Print a formatted error message and exit the script
# Usage: error_exit "Your error message" [exit_code]
error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    echo -e "${RED} ERROR: $message${RESET}" >&2
    # The 'exit' command will trigger the 'trap cleanup'.
    exit "$exit_code"
}

# --- Messaging Functions ---
success_message() { echo -e "${GREEN}✓ $1${RESET}"; }
warning_message() { echo -e "${YELLOW}⚠ WARNING: $1${RESET}"; }
info_message() { echo -e "${CYAN}$1${RESET}"; }
debug_message() {
    # Only print if the DEBUG variable is set to a non-zero integer.
    if (( DEBUG )); then
        echo -e "${YELLOW}DEBUG: $1${RESET}" >&2
    fi
}


# --- Secure Temporary Directory Initialization ---
# Creates a secure, private temporary directory in memory (/dev/shm) if possible,
# falling back to other locations. This directory is automatically cleaned up on exit
init_secure_temp() {
    # Prefer memory-backed tmpfs for speed and security (no disk writes)
    local temp_locations=("/dev/shm" "/tmp" "$(pwd)")
    for loc in "${temp_locations[@]}"; do
        # Check if the location exists and is writable before trying
        if [[ -d "$loc" && -w "$loc" ]]; then
            # mktemp creates a directory with a unique random name
            SECURE_TMPDIR=$(mktemp -d -p "$loc" "securecrypt.XXXXXX")
            if [[ -n "$SECURE_TMPDIR" && -d "$SECURE_TMPDIR" ]]; then
                debug_message "Secure temp dir created at: $SECURE_TMPDIR"
                return 0
            fi
        fi
    done
    error_exit "Failed to create a secure temporary directory."
}

# --- Dependency Check ---
# Verifies that all required command-line tools (openssl, tar) are installed.
check_dependencies() {
    info_message "Checking for required tools..."
    local missing_tools=()
    for tool in "openssl" "tar" "head" "tail" "xxd" "cmp"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if (( ${#missing_tools[@]} > 0 )); then
        error_exit "Missing required tools: ${missing_tools[*]}. Please install them and try again."
    fi
    success_message "All dependencies are satisfied."
}

# ==============================================================================
# ENCRYPTION LOGIC
# ==============================================================================

# --- Generate Session Key Bundle ---
# Creates a temporary file containing the AES key and the HMAC key
# This bundle is what will be encrypted with the RSA public key
# Arguments: $1: Output file path for the key bundle
generate_session_key_bundle() {
    local bundle_file="$1"
    info_message "Generating secure AES and HMAC keys..."
    # Generate cryptographically secure random bytes for both keys at once.
    if ! openssl rand "$((AES_KEY_SIZE + HMAC_KEY_SIZE))" > "$bundle_file"; then
        error_exit "Failed to generate session key bundle."
    fi
    success_message "Session key bundle generated."
}

# --- Encrypt Session Key with RSA ---
# Encrypts the session key bundle using the provided RSA public key
# Prefers OAEP padding for security, with a fallback for older keys
# Arguments: $1: Path to session key bundle, $2: Path to RSA public key, $3: Output path for encrypted key
encrypt_key_with_rsa() {
    local bundle_file="$1"
    local rsa_pub_key="$2"
    local encrypted_key_file="$3"
    info_message "Encrypting session key with RSA public key..."

    # Try with RSA-OAEP padding (modern standard).
    if ! openssl pkeyutl -encrypt \
        -pubin -inkey "$rsa_pub_key" \
        -in "$bundle_file" \
        -out "$encrypted_key_file" \
        -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha256 &>/dev/null; then

        warning_message "RSA-OAEP padding failed. Trying legacy PKCS1_v1.5 padding..."
        # Fallback to PKCS1 padding if OAEP is not supported by the key.
        if ! openssl pkeyutl -encrypt \
            -pubin -inkey "$rsa_pub_key" \
            -in "$bundle_file" \
            -out "$encrypted_key_file" \
            -pkeyopt rsa_padding_mode:pkcs1 &>/dev/null; then
            error_exit "Failed to encrypt session key with RSA. The key may be invalid or unsupported."
        fi
    fi
    success_message "Session key encrypted successfully."
}

# --- Main File Encryption and Packaging ---
# Encrypts the file and creates the final tar archive.
# Arguments: $1: Input file, $2: Session key bundle, $3: Output tar file
encrypt_file_and_package() {
    local input_file="$1"
    local key_bundle_file="$2"
    local output_tar_file="$3"

    # --- Create temporary files within the secure directory ---
    local aes_key_file iv_file hmac_key_file ciphertext_file hmac_file
    aes_key_file=$(mktemp -p "$SECURE_TMPDIR")
    iv_file=$(mktemp -p "$SECURE_TMPDIR")
    hmac_key_file=$(mktemp -p "$SECURE_TMPDIR")
    ciphertext_file=$(mktemp -p "$SECURE_TMPDIR")
    hmac_file=$(mktemp -p "$SECURE_TMPDIR")

    # --- Extract AES and HMAC keys from the bundle using head/tail (used like this for portability) ---
    info_message "Splitting session key into AES and HMAC keys..."
    if ! head -c "$AES_KEY_SIZE" "$key_bundle_file" > "$aes_key_file" || \
       ! tail -c "$HMAC_KEY_SIZE" "$key_bundle_file" > "$hmac_key_file"; then
        error_exit "Failed to split the session key bundle."
    fi

    # --- Generate a random IV ---
    info_message "Generating random IV..."
    openssl rand "$IV_SIZE" > "$iv_file"

    # --- Encrypt the file with AES-256-CBC ---
    info_message "Encrypting file with AES-256-CBC..."
    if ! openssl enc -aes-256-cbc -e \
        -in "$input_file" \
        -out "$ciphertext_file" \
        -K "$(xxd -p -c 256 "$aes_key_file")" \
        -iv "$(xxd -p -c 256 "$iv_file")"; then
        error_exit "AES encryption failed."
    fi

    # --- Calculate HMAC-SHA256 of the CIPHERTEXT (Encrypt-then-MAC) ---
    # Save only the binary HMAC
    info_message "Calculating HMAC-SHA256 for integrity protection..."
    if ! openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(xxd -p -c 256 "$hmac_key_file")" \
        -binary "$ciphertext_file" > "$hmac_file"; then
        error_exit "HMAC calculation failed."
    fi

    # --- RENAME temporary files to their final names for archiving ---
    local final_ciphertext="$SECURE_TMPDIR/ciphertext.bin"
    local final_iv="$SECURE_TMPDIR/iv.bin"
    local final_hmac="$SECURE_TMPDIR/hmac.bin"
    mv "$ciphertext_file" "$final_ciphertext"
    mv "$iv_file" "$final_iv"
    mv "$hmac_file" "$final_hmac"

    # --- Package everything into a single tar archive ---
    info_message "Creating final encrypted package..."
    if ! tar -cf "$output_tar_file" \
        -C "$SECURE_TMPDIR" \
        "ciphertext.bin" \
        "iv.bin" \
        "hmac.bin"; then
        error_exit "Failed to create final tar package."
    fi

    success_message "File encrypted and packaged successfully."
}

# --- Create Metadata File ---
# Generates a JSON file with information about the encryption process.
# Arguments: $1: Metadata output path, $2: Original file path, $3: Encrypted tar path
create_metadata_file() {
    local metadata_file="$1"
    local original_file="$2"
    local encrypted_tar_file="$3"
    info_message "Creating metadata file..."

    # Use `stat` command, checking for macOS/BSD and Linux variants.
    local original_size
    if stat -f%z "$original_file" &>/dev/null; then
        original_size=$(stat -f%z "$original_file") # macOS/BSD
    else
        original_size=$(stat -c%s "$original_file") # Linux
    fi

    # JSON content is written to the file.
    cat > "$metadata_file" << EOF
{
  "version": "2.3",
  "encryptionTimestampUTC": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "encryptionAlgorithm": "AES-256-CBC",
  "authenticationAlgorithm": "HMAC-SHA256",
  "keyEncryptionAlgorithm": "RSA-OAEP-SHA256 (fallback PKCS1)",
  "originalFilename": "$(basename "$original_file")",
  "originalSizeBytes": $original_size,
  "originalFileSHA256": "$(openssl dgst -sha256 -hex "$original_file" | sed 's/.* //')"
}
EOF
    success_message "Metadata file created."
}

# ==============================================================================
# DECRYPTION LOGIC
# ==============================================================================

# --- Decrypt Session Key with RSA ---
# Decrypts the session key bundle using the user's RSA private key.
# Arguments: $1: Encrypted key file, $2: RSA private key, $3: Output for decrypted bundle
decrypt_key_with_rsa() {
    local encrypted_key_file="$1"
    local rsa_priv_key="$2"
    local decrypted_bundle_file="$3"
    info_message "Decrypting session key with RSA private key..."

    # Try with OAEP padding first.
    if ! openssl pkeyutl -decrypt \
        -inkey "$rsa_priv_key" \
        -in "$encrypted_key_file" \
        -out "$decrypted_bundle_file" \
        -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha256 &>/dev/null; then

        warning_message "RSA-OAEP decryption failed. Trying legacy PKCS1_v1.5 padding..."
        # Fallback to PKCS1.
        if ! openssl pkeyutl -decrypt \
            -inkey "$rsa_priv_key" \
            -in "$encrypted_key_file" \
            -out "$decrypted_bundle_file" \
            -pkeyopt rsa_padding_mode:pkcs1 &>/dev/null; then
            error_exit "Failed to decrypt session key. The private key may be incorrect, password-protected, or does not match the public key used for encryption."
        fi
    fi
    success_message "Session key decrypted successfully."
}

# --- Unpack, Verify, and Decrypt File ---
# The core decryption process.
# Arguments: $1: Input tar archive, $2: Decrypted key bundle, $3: Output file for decrypted content
unpack_and_decrypt_file() {
    local input_tar_file="$1"
    local key_bundle_file="$2"
    local output_file="$3"

    # --- Create a temporary directory for unpacking the tar archive ---
    local unpack_dir
    unpack_dir=$(mktemp -d -p "$SECURE_TMPDIR")
    info_message "Unpacking encrypted archive..."
    if ! tar -xf "$input_tar_file" -C "$unpack_dir"; then
        error_exit "Failed to unpack the encrypted tar archive. It may be corrupt."
    fi

    # --- Define paths to unpacked components ---
    local ciphertext_file="$unpack_dir/ciphertext.bin"
    local iv_file="$unpack_dir/iv.bin"
    local received_hmac_file="$unpack_dir/hmac.bin"

    # --- Extract AES and HMAC keys from the decrypted bundle ---
    local aes_key_file hmac_key_file
    aes_key_file=$(mktemp -p "$SECURE_TMPDIR")
    hmac_key_file=$(mktemp -p "$SECURE_TMPDIR")
    info_message "Splitting decrypted session key..."
    if ! head -c "$AES_KEY_SIZE" "$key_bundle_file" > "$aes_key_file" || \
       ! tail -c "$HMAC_KEY_SIZE" "$key_bundle_file" > "$hmac_key_file"; then
        error_exit "Failed to split the decrypted session key bundle."
    fi

    # --- VERIFY INTEGRITY FIRST ---
    info_message "Verifying file integrity with HMAC-SHA256..."
    local calculated_hmac_file
    calculated_hmac_file=$(mktemp -p "$SECURE_TMPDIR")
    #Calculate HMAC in binary format
    if ! openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(xxd -p -c 256 "$hmac_key_file")" \
        -binary "$ciphertext_file" > "$calculated_hmac_file"; then
        error_exit "HMAC recalculation failed during verification."
    fi

    # --- DEBUGGING BLOCK ---
    # This block will only run if the DEBUG variable is set to 1
    # It prints the keys and hashes to help diagnose HMAC mismatches if so
    if (( DEBUG )); then
        debug_message "--- HMAC Verification Details ---"
        debug_message "HMAC Key Used (hex):   $(xxd -p -c 256 "$hmac_key_file")"
        debug_message "Received HMAC (hex):   $(xxd -p -c 256 "$received_hmac_file")"
        debug_message "Calculated HMAC (hex): $(xxd -p -c 256 "$calculated_hmac_file")"
        debug_message "Ciphertext file size:  $(stat -c%s "$ciphertext_file" 2>/dev/null || stat -f%z "$ciphertext_file" 2>/dev/null)"
        debug_message "Received HMAC size:    $(stat -c%s "$received_hmac_file" 2>/dev/null || stat -f%z "$received_hmac_file" 2>/dev/null)"
        debug_message "Calculated HMAC size:  $(stat -c%s "$calculated_hmac_file" 2>/dev/null || stat -f%z "$calculated_hmac_file" 2>/dev/null)"
        debug_message "--- End HMAC Details ---"
    fi

    # Compare the received HMAC with the calculated one.
    if ! cmp -s "$received_hmac_file" "$calculated_hmac_file"; then
        error_exit "HMAC verification FAILED! The encrypted file has been tampered with or is corrupt. Decryption aborted."
    fi
    success_message "Integrity check passed. The file is authentic."

    # --- Decrypt the file ---
    info_message "Decrypting file with AES-256-CBC..."
    if ! openssl enc -aes-256-cbc -d \
        -in "$ciphertext_file" \
        -out "$output_file" \
        -K "$(xxd -p -c 256 "$aes_key_file")" \
        -iv "$(xxd -p -c 256 "$iv_file")"; then
        error_exit "AES decryption failed. The data may be corrupt."
    fi
    success_message "File decrypted successfully."
}

# ==============================================================================
# MAIN SCRIPT FLOW
# ==============================================================================

# --- Display Banner ---
display_banner() {
    clear
    echo -e "${BLUE}"
    cat << 'EOF'
 _    ____________  _____ ____     ____________  ______  ______
| |  / / ____/ __ \/ ___// __ \   / ____/ __ \ \/ / __ \/_  __/
| | / / __/ / /_/ /\__ \/ / / /  / /   / /_/ /\  / /_/ / / /
| |/ / /___/ _, _/___/ / /_/ /  / /___/ _, _/ / / ____/ / /
|___/_____/_/ |_|/____/\____/   \____/_/ |_| /_/_/     /_/

EOF
    echo -e "${RESET}"
    echo -e "${GREEN}    ✩░▒▓▆▅▃▂  Encryption Tool made by aFlavius04  ▂▃▅▆▓▒░✩${RESET}"
    echo -e "${CYAN}    AES-256-CBC + HMAC-SHA256 authenticated by RSA-OAEP${RESET}"
    echo ""
}

# --- Usage Information ---
usage() {
    echo "Usage: $SCRIPT_NAME [encrypt|decrypt]"
    echo ""
    echo "  encrypt: Interactively encrypt a file."
    echo "  decrypt: Interactively decrypt a file."
    echo ""
    exit 1
}

# --- Main Encryption Workflow ---
main_encrypt() {
    # --- Get user input ---
    info_message "--- Starting Encryption ---"
    read -rp "Enter the full path to the file to encrypt: " input_file
    input_file="${input_file/#\~/$HOME}" # Expand tilde
    [[ -z "$input_file" ]] && error_exit "Input file cannot be empty."
    [[ ! -f "$input_file" ]] && error_exit "Input file not found: $input_file"

    read -rp "Enter path to the RSA PUBLIC key for the recipient: " rsa_pub_key
    rsa_pub_key="${rsa_pub_key/#\~/$HOME}"
    [[ -z "$rsa_pub_key" ]] && error_exit "RSA public key path cannot be empty."
    [[ ! -f "$rsa_pub_key" ]] && error_exit "RSA public key not found: $rsa_pub_key"

    local base_name="${input_file##*/}"
    local default_output_base="${base_name%.*}_$(date +%Y%m%d)"
    read -rp "Enter a base name for output files [${default_output_base}]: " output_base
    output_base="${output_base:-$default_output_base}"

    local encrypted_tar_file="${output_base}.enc.tar"
    local encrypted_key_file="${output_base}.key.enc"
    local metadata_file="${output_base}.meta.json"

    # --- Confirm before overwriting ---
    for f in "$encrypted_tar_file" "$encrypted_key_file" "$metadata_file"; do
        if [[ -e "$f" ]]; then
            read -rp "$(warning_message "File '$f' exists. Overwrite? [y/N]: ")" confirm
            [[ ! "$confirm" =~ ^[yY]$ ]] && error_exit "Operation cancelled by user."
        fi
    done

    # --- Execute encryption steps ---
    local temp_key_bundle
    temp_key_bundle=$(mktemp -p "$SECURE_TMPDIR")

    generate_session_key_bundle "$temp_key_bundle"
    encrypt_key_with_rsa "$temp_key_bundle" "$rsa_pub_key" "$encrypted_key_file"
    encrypt_file_and_package "$input_file" "$temp_key_bundle" "$encrypted_tar_file"
    create_metadata_file "$metadata_file" "$input_file" "$encrypted_tar_file"

    # --- Final success message ---
    echo ""
    success_message "=== ENCRYPTION COMPLETE ==="
    echo "Original file: $input_file"
    echo "Outputs created:"
    echo "  - Encrypted Package: $encrypted_tar_file"
    echo "  - Encrypted Key:     $encrypted_key_file"
    echo "  - Metadata:          $metadata_file"
    echo ""
    info_message "Send these three files to the recipient. They will need their RSA private key to decrypt."
}

# --- Main Decryption Workflow ---
main_decrypt() {
    # --- Get user input ---
    info_message "--- Starting Decryption ---"
    read -rp "Enter path to the encrypted package (*.enc.tar): " encrypted_tar_file
    encrypted_tar_file="${encrypted_tar_file/#\~/$HOME}"
    [[ ! -f "$encrypted_tar_file" ]] && error_exit "Encrypted package not found: $encrypted_tar_file"

    read -rp "Enter path to the encrypted key file (*.key.enc): " encrypted_key_file
    encrypted_key_file="${encrypted_key_file/#\~/$HOME}"
    [[ ! -f "$encrypted_key_file" ]] && error_exit "Encrypted key file not found: $encrypted_key_file"

    read -rp "Enter path to YOUR RSA PRIVATE key: " rsa_priv_key
    rsa_priv_key="${rsa_priv_key/#\~/$HOME}"
    [[ ! -f "$rsa_priv_key" ]] && error_exit "RSA private key not found: $rsa_priv_key"

    local default_output="decrypted_$(basename "${encrypted_tar_file%.enc.tar}")"
    read -rp "Enter name for the decrypted output file [${default_output}]: " output_file
    output_file="${output_file:-$default_output}"

    if [[ -e "$output_file" ]]; then
        read -rp "$(warning_message "Output file '$output_file' exists. Overwrite? [y/N]: ")" confirm
        [[ ! "$confirm" =~ ^[yY]$ ]] && error_exit "Operation cancelled by user."
    fi

    # --- Execute decryption steps ---
    local temp_decrypted_bundle
    temp_decrypted_bundle=$(mktemp -p "$SECURE_TMPDIR")

    decrypt_key_with_rsa "$encrypted_key_file" "$rsa_priv_key" "$temp_decrypted_bundle"
    unpack_and_decrypt_file "$encrypted_tar_file" "$temp_decrypted_bundle" "$output_file"

    # --- Final success message ---
    echo ""
    success_message "=== DECRYPTION COMPLETE ==="
    echo "Decrypted content saved to: $output_file"
}


# --- Script Entry Point ---
main() {
    display_banner
    check_dependencies
    init_secure_temp

    # Check for command line argument (encrypt or decrypt)
    if [[ $# -eq 0 ]]; then
        usage
    fi

    case "$1" in
        encrypt)
            main_encrypt
            ;;
        decrypt)
            main_decrypt
            ;;
        *)
            echo -e "${RED}Invalid mode: $1${RESET}\n"
            usage
            ;;
    esac
}

# Ensure the script is not being sourced and then run main.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi