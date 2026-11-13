#!/bin/bash
# ==============================================================================
# ObFUSEcate
# obfusecate{.sh}
# 
# Author: Travis J. Galoppo (tgaloppo@gmail.com)
# 
# SPDX-License-Identifier: MIT
# ==============================================================================

set -e

# Locate the daemon binary
DAEMON_BIN=$(which obfusecate_daemon 2>/dev/null || true)
if [[ -z "$DAEMON_BIN" ]]; then
    # Fallback to local directory structure if not in $PATH
    if [[ -x "./obfusecate_daemon" ]]; then
        DAEMON_BIN="./obfusecate_daemon"
    elif [[ -x "./bin/obfusecate_daemon" ]]; then
        DAEMON_BIN="./bin/obfusecate_daemon"
    else
        echo "Error: Could not find 'obfusecate_daemon' binary in PATH or current directory."
        exit 1
    fi
fi

COMMAND=$1

if [[ "$COMMAND" == "umount" ]]; then
    MOUNT_POINT=$2
    if [[ -z "$MOUNT_POINT" ]]; then
        echo "Usage: $0 umount <mount_point>"
        exit 1
    fi

    MOUNT_POINT="${MOUNT_POINT%/}"
    PARENT_DIR=$(dirname "$MOUNT_POINT")
    BASE_NAME=$(basename "$MOUNT_POINT")
    BRIDGE_DIR="${PARENT_DIR}/.${BASE_NAME}_bridge"
    
    echo "Unmounting ext4 volume..."
    fusermount3 -u "$MOUNT_POINT" || true
    
    echo "Waiting for ext4 to flush caches and release the block device..."
    while fuser "$BRIDGE_DIR/data" >/dev/null 2>&1; do
        sleep 0.2
    done
    
    # automatically perform block compaction if zerofree is installed
    if command -v zerofree >/dev/null 2>&1; then
        echo "Compacting unused blocks..."
        zerofree "$BRIDGE_DIR/data" || echo "Warning: zerofree encountered a minor issue."
    else
        echo "'zerofree' not installed; skipping automatic block compaction."
    fi
    
    echo "Unmounting ObFUSEcate bridge..."
    MAX_RETRIES=20
    COUNT=0
    while ! fusermount3 -u "$BRIDGE_DIR" 2>/dev/null; do
        sleep 0.5
        COUNT=$((COUNT + 1))
        if [[ $COUNT -ge $MAX_RETRIES ]]; then
            echo "Error: Bridge is still busy. Is another process locking it?"
            exit 1
        fi
    done
    
    rmdir "$BRIDGE_DIR" 2>/dev/null || true
    
    echo "Volume successfully unmounted."
    exit 0
fi

if [[ "$COMMAND" == "format" ]]; then
    VOL_FILE=$2
    MOUNT_POINT=$3
    SIZE=$4
    KEY_ARG=$5

    if [[ -z "$SIZE" ]]; then
        echo "Usage: $0 format <volume_file> <mount_point> <size> [key_file]"
        echo "Example: $0 format my_vol.ofs ~/secure 100M"
        exit 1
    fi

    # fail if the vault already exists to prevent data loss
    if [[ -e "$VOL_FILE" ]]; then
        echo "Error: Volume file '$VOL_FILE' already exists. Aborting format."
        exit 1
    fi    
elif [[ "$COMMAND" == "mount" ]]; then
    VOL_FILE=$2
    MOUNT_POINT=$3
    KEY_ARG=$4

    if [[ -z "$MOUNT_POINT" ]]; then
        echo "Usage: $0 mount <volume_file> <mount_point> [key_file]"
        exit 1
    fi
else
    echo "Usage:"
    echo "  $0 format <volume_file> <mount_point> <size> [key_file]"
    echo "  $0 mount <volume_file> <mount_point> [key_file]"
    echo "  $0 umount <mount_point>"
    exit 1
fi

MOUNT_POINT="${MOUNT_POINT%/}"
PARENT_DIR=$(dirname "$MOUNT_POINT")
BASE_NAME=$(basename "$MOUNT_POINT")
BRIDGE_DIR="${PARENT_DIR}/.${BASE_NAME}_bridge"

fusermount3 -u "$MOUNT_POINT" 2>/dev/null || true
fusermount3 -u "$BRIDGE_DIR" 2>/dev/null || true

mkdir -p "$BRIDGE_DIR"
mkdir -p "$MOUNT_POINT"

# 1. Handle Key Management
CLEANUP_KEY=0
if [[ -n "$KEY_ARG" && -f "$KEY_ARG" ]]; then
    KEY_FILE="$KEY_ARG"
else
    read -s -p "Enter Volume Password: " VOL_PASS
    echo
    if [[ "$COMMAND" == "format" ]]; then
        read -s -p "Confirm Password: " VOL_PASS_CONFIRM
        echo
        if [[ "$VOL_PASS" != "$VOL_PASS_CONFIRM" ]]; then
            echo "Passwords do not match. Aborting."
            exit 1
        fi
    fi

    # Create transient RAM-disk file for the hashed password
    KEY_FILE=$(mktemp /dev/shm/obfusecate.XXXXXX)
    chmod 600 "$KEY_FILE"
    CLEANUP_KEY=1
    
    echo -n "$VOL_PASS" | sha256sum | awk '{print $1}' | xxd -r -p > "$KEY_FILE"
fi

cleanup() {
    if [[ $CLEANUP_KEY -eq 1 && -f "$KEY_FILE" ]]; then
        shred -u "$KEY_FILE" 2>/dev/null || rm -f "$KEY_FILE"
    fi
}
trap cleanup EXIT

# 2. Start ObFUSEcate Daemon on the Bridge Directory
if [[ "$COMMAND" == "format" ]]; then
    touch "$VOL_FILE"
fi

echo "Starting ObFUSEcate on bridge: $BRIDGE_DIR..."
if ! "$DAEMON_BIN" "$VOL_FILE" "$KEY_FILE" "$BRIDGE_DIR" "-s"; then
    echo "Failed to start ObFUSEcate. Incorrect password/key or corrupt volume?"
    exit 1
fi

# Wait for the virtual block device to appear
while [[ ! -f "$BRIDGE_DIR/data" ]]; do
    sleep 0.1
done

# 3. Format ext4 if needed
if [[ "$COMMAND" == "format" ]]; then
    echo "Setting logical volume size to $SIZE..."
    truncate -s "$SIZE" "$BRIDGE_DIR/data"
    
    echo "Formatting ext4 filesystem..."
    mkfs.ext4 -F -m 0 -O ^has_journal -E root_owner=$(id -u):$(id -g) "$BRIDGE_DIR/data"
fi

# 4. Mount ext4 via fuse2fs
echo "Mounting ext4 filesystem to $MOUNT_POINT..."
if fuse2fs "$BRIDGE_DIR/data" "$MOUNT_POINT"; then
    echo "Volume successfully mounted at $MOUNT_POINT!"
else
    echo "Failed to mount ext4 filesystem."
    fusermount3 -u "$BRIDGE_DIR" || true
    exit 1
fi
