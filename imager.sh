#!/bin/bash

# Comprehensive Forensic Disk Duplicator Script with Optional GPIO Support

set -euo pipefail

# Global variables
SCRIPT_NAME=$(basename "$0")
LOG_FILE="/var/log/${SCRIPT_NAME%.*}.log"
REQUIRED_CMDS=("dd" "openssl" "aws" "pv" "lsblk" "grep" "awk" "sed" "tr" "tee" "date" "basename" "sha256sum")

# GPIO settings (only used if GPIO_ENABLED is set to "true")
GPIO_ENABLED=${GPIO_ENABLED:-false}
LED_PIN=18
GPIO_CMD="gpio"

# Function to log messages
log() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Function to display usage
usage() {
    echo "Usage: ENCRYPTION_KEY='your_secret_key' [GPIO_ENABLED=true] $0 <source_disk> <s3_bucket>"
    echo "Example: ENCRYPTION_KEY='mySecretKey' GPIO_ENABLED=true $0 /dev/sda my-forensic-bucket"
    echo "If source_disk is omitted, available unmounted disks will be displayed."
    exit 1
}

# Function to check for required commands
check_commands() {
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log "Error: $cmd could not be found. Please install it."
            exit 1
        fi
    done
    if [ "$GPIO_ENABLED" = true ] && ! command -v "$GPIO_CMD" &> /dev/null; then
        log "Error: GPIO support is enabled but 'gpio' command is not found. Please install wiringpi."
        exit 1
    fi
    log "All required commands are available."
}

# Function to set up GPIO
setup_gpio() {
    if [ "$GPIO_ENABLED" = true ]; then
        log "Setting up GPIO..."
        $GPIO_CMD -g mode $LED_PIN out
        $GPIO_CMD -g write $LED_PIN 0
    fi
}

# Function to clean up GPIO
cleanup_gpio() {
    if [ "$GPIO_ENABLED" = true ]; then
        log "Cleaning up GPIO..."
        $GPIO_CMD -g write $LED_PIN 0
    fi
}

# Function to blink LED
blink_led() {
    if [ "$GPIO_ENABLED" = true ]; then
        while true; do
            $GPIO_CMD -g write $LED_PIN 1
            sleep 0.5
            $GPIO_CMD -g write $LED_PIN 0
            sleep 0.5
        done
    fi
}

# Function to list unmounted disks
list_unmounted_disks() {
    log "Listing available unmounted disks:"
    lsblk -dpno NAME,SIZE,TYPE,MOUNTPOINT | grep -v "/" | awk '$3=="disk" {print $1 " (" $2 ")"}'
}

# Function to remove incomplete upload
remove_incomplete_upload() {
    log "Removing incomplete upload from S3..."
    if ! aws s3 rm "s3://${S3_BUCKET}/${OUTPUT_FILE}"; then
        log "Warning: Failed to remove incomplete upload from S3. Manual cleanup may be necessary."
    fi
}

# Function to generate filename from drive metadata
generate_filename() {
    local drive=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Fetch drive details
    local model=$(lsblk -ndo MODEL "$drive" | tr ' ' '_')
    local serial=$(lsblk -ndo SERIAL "$drive" | tr ' ' '_')
    local size=$(lsblk -ndo SIZE "$drive" | tr -d ' ')
    local vendor=$(lsblk -ndo VENDOR "$drive" | tr ' ' '_')
    
    # Fallback for model if unavailable
    if [ -z "$model" ]; then
        if [ -n "$vendor" ]; then
            model="${vendor}_unknown_model"
        else
            model="unknown_model"
        fi
    fi
    
    # Fallback for serial if unavailable
    if [ -z "$serial" ]; then
        # Use last 8 characters of drive UUID as a unique identifier
        serial=$(lsblk -ndo UUID "$drive" | tail -c 9)
        if [ -z "$serial" ]; then
            # If UUID is also unavailable, use a portion of the drive name
            serial=$(echo "$drive" | sed 's/.*\///;s/[^a-zA-Z0-9]/_/g')
        fi
        serial="no_serial_${serial}"
    fi
    
    echo "${timestamp}_${model}_${serial}_${size}.img.enc"
}

# Function to calculate SHA256 hash
calculate_sha256() {
    local drive=$1
    log "Calculating SHA256 hash of $drive..."
    local sha256=$(dd if="$drive" bs=4M status=none | sha256sum | awk '{print $1}')
    log "SHA256 hash: $sha256"
    echo "$sha256"
}

# Main function
main() {
    log "Starting $SCRIPT_NAME"

    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        log "Error: Please run as root"
        exit 1
    fi

    # Check for required commands
    check_commands

    # Set up GPIO if enabled
    setup_gpio
    trap cleanup_gpio EXIT

    # Check for encryption key
    if [ -z "${ENCRYPTION_KEY:-}" ]; then
        log "Error: ENCRYPTION_KEY environment variable is not set."
        usage
    fi

    # Parse arguments
    if [ $# -eq 1 ]; then
        list_unmounted_disks
        exit 0
    elif [ $# -eq 2 ]; then
        SOURCE_DISK=$1
        S3_BUCKET=$2
    else
        usage
    fi

    # Verify source disk exists
    if [ ! -b "$SOURCE_DISK" ]; then
        log "Error: $SOURCE_DISK is not a valid block device."
        list_unmounted_disks
        exit 1
    fi

    # Generate output filename
    OUTPUT_FILE=$(generate_filename "$SOURCE_DISK")
    log "Generated output filename: $OUTPUT_FILE"

    # Explain filename components
    log "Filename components:"
    log "  Timestamp: $(echo "$OUTPUT_FILE" | cut -d'_' -f1)"
    log "  Model: $(echo "$OUTPUT_FILE" | cut -d'_' -f2)"
    log "  Serial: $(echo "$OUTPUT_FILE" | cut -d'_' -f3)"
    log "  Size: $(echo "$OUTPUT_FILE" | cut -d'_' -f4 | sed 's/\.img\.enc//')"

    # Calculate SHA256 hash before duplication
    SHA256_BEFORE=$(calculate_sha256 "$SOURCE_DISK")

    # Start the duplication process
    log "Starting disk duplication of $SOURCE_DISK"

    # Start LED blinking in background if GPIO is enabled
    if [ "$GPIO_ENABLED" = true ]; then
        blink_led &
        BLINK_PID=$!
    fi

    # Use dd to read the disk, pipe through openssl for encryption, 
    # then to pv for progress, and finally to aws s3 for upload
    if ! dd if="$SOURCE_DISK" bs=4M status=none | \
         openssl enc -aes-256-cbc -salt -pbkdf2 -k "$ENCRYPTION_KEY" 2>> "$LOG_FILE" | \
         pv -pterb | \
         aws s3 cp - "s3://${S3_BUCKET}/${OUTPUT_FILE}" 2>> "$LOG_FILE"; then
        log "Error: Disk duplication failed"
        remove_incomplete_upload
        if [ "$GPIO_ENABLED" = true ]; then
            kill $BLINK_PID
            $GPIO_CMD -g write $LED_PIN 0
        fi
        exit 1
    fi

    # Stop LED blinking and set to solid if GPIO is enabled
    if [ "$GPIO_ENABLED" = true ]; then
        kill $BLINK_PID
        $GPIO_CMD -g write $LED_PIN 1
    fi

    log "Disk duplication completed successfully"

    # Calculate SHA256 hash after duplication
    SHA256_AFTER=$(calculate_sha256 "$SOURCE_DISK")

    # Compare hashes
    if [ "$SHA256_BEFORE" != "$SHA256_AFTER" ]; then
        log "Warning: SHA256 hash mismatch. The source disk may have changed during duplication."
        log "  Before: $SHA256_BEFORE"
        log "  After:  $SHA256_AFTER"
    else
        log "SHA256 hash verification successful. Source disk remained unchanged during duplication."
    fi

    log "Encrypted disk image uploaded to s3://${S3_BUCKET}/${OUTPUT_FILE}"
    log "Please store the SHA256 hash securely for later verification"

    # Clear the encryption key from the environment
    unset ENCRYPTION_KEY

    # Turn off LED if GPIO is enabled
    if [ "$GPIO_ENABLED" = true ]; then
        $GPIO_CMD -g write $LED_PIN 0
    fi

    log "$SCRIPT_NAME completed successfully"
}

# Run main function
main "$@"
