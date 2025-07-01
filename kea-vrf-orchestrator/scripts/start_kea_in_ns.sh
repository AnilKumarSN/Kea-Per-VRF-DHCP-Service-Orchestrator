#!/bin/bash
# Helper script to start a Kea instance in a specified namespace.

set -e

NS_NAME="$1"
KEA_SERVICE="$2" # "kea-dhcp4" or "kea-dhcp6"
KEA_CONFIG_FILE="$3"

if [ -z "$NS_NAME" ] || [ -z "$KEA_SERVICE" ] || [ -z "$KEA_CONFIG_FILE" ]; then
    echo "Usage: $0 <namespace_name> <kea_service_command> <kea_config_file_path>"
    echo "Example: $0 vrf-blue_ns kea-dhcp4 /etc/kea/kea-dhcp4-vrf-blue.conf"
    exit 1
fi

if ! ip netns list | grep -q "^$NS_NAME"; then
    echo "[ERROR] Network namespace '$NS_NAME' does not exist."
    exit 1
fi

if [ ! -f "$KEA_CONFIG_FILE" ]; then
    echo "[ERROR] Kea config file '$KEA_CONFIG_FILE' not found."
    exit 1
fi

if ! command -v "$KEA_SERVICE" &> /dev/null; then
    echo "[ERROR] Kea service command '$KEA_SERVICE' not found. Is Kea installed and in PATH?"
    exit 1
fi

echo "[INFO] Starting $KEA_SERVICE in namespace $NS_NAME with config $KEA_CONFIG_FILE"

# Create leases file directory if it doesn't exist, assuming memfile and path like /var/lib/kea/
# This depends on the Kea configuration. For memfile, it might write to a path.
# Example: if config contains "lease-database": { "type": "memfile", "name": "/var/lib/kea/kea-leases4.csv" }
LEASE_FILE_PATH=$(grep -oP '"name":\s*"\K[^"]+' "$KEA_CONFIG_FILE" | head -n 1)
if [ -n "$LEASE_FILE_PATH" ]; then
    LEASE_DIR=$(dirname "$LEASE_FILE_PATH")
    # Check if the lease dir is within the namespace's expected filesystem view.
    # For simplicity, we assume it's a standard path that needs to be accessible.
    # `ip netns exec` doesn't virtualize the filesystem by default beyond /sys and /proc bits.
    # So, we create it on the host, and Kea running in the namespace will access it.
    if [ ! -d "$LEASE_DIR" ]; then
        echo "[INFO] Creating directory for Kea lease file: $LEASE_DIR"
        sudo mkdir -p "$LEASE_DIR"
        # Kea typically runs as a non-root user, e.g., 'kea' or '_kea'.
        # Adjust ownership if your Kea runs as a specific user.
        # sudo chown kea:kea "$LEASE_DIR"
    fi
else
    echo "[INFO] Could not determine lease file path from config, or it's not 'name'. Manual setup of lease persistence might be needed."
fi

LOG_DIR="/var/log/kea"
if [ ! -d "$LOG_DIR" ]; then
    echo "[INFO] Creating Kea log directory: $LOG_DIR"
    sudo mkdir -p "$LOG_DIR"
    # sudo chown kea:kea "$LOG_DIR" # If Kea runs as a specific user
fi


# Run Kea in the background
# The -d flag for debug/verbose logging can be useful.
# Output will typically go to syslog or files configured in Kea's logging section.
sudo ip netns exec "$NS_NAME" "$KEA_SERVICE" -c "$KEA_CONFIG_FILE" &
KEA_PID=$!

echo "[INFO] $KEA_SERVICE started in $NS_NAME with PID $KEA_PID."
echo "To check status, use 'ps aux | grep $KEA_SERVICE' or check Kea logs."
echo "To stop: sudo kill $KEA_PID"

# Give Kea a moment to start up and potentially report initial errors
sleep 2
if ! ps -p $KEA_PID > /dev/null; then
   echo "[ERROR] $KEA_SERVICE (PID $KEA_PID) failed to stay running. Check logs (e.g., /var/log/kea/kea.log or syslog)."
   exit 1
fi

chmod +x kea-vrf-orchestrator/scripts/start_kea_in_ns.sh
