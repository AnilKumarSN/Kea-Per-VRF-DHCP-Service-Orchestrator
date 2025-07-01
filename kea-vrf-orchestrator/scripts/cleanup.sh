#!/bin/bash
# Helper script to clean up VRFs, namespaces, veth pairs, and kill Kea instances.

set -e
# set -x

DEFAULT_VRF_NAME_PATTERN="vrf-" # Default pattern to identify VRFs managed by this system
VRF_NAME_PATTERN="${1:-$DEFAULT_VRF_NAME_PATTERN}"

echo "--- Starting Cleanup Process ---"

# 1. Kill Kea processes
# This is a bit broad; ideally, we'd track PIDs.
# For a script, killing by name is common but use with caution.
echo "[INFO] Attempting to stop Kea DHCP servers (kea-dhcp4, kea-dhcp6)..."
sudo pkill -f "kea-dhcp4" || echo "[INFO] kea-dhcp4 not found or already stopped."
sudo pkill -f "kea-dhcp6" || echo "[INFO] kea-dhcp6 not found or already stopped."
sleep 1 # Give processes time to terminate

# 2. Delete veth pairs and network namespaces
# Assuming naming convention:
# Namespace: <vrf_name>_ns
# Veth host: veth_<vrf_name>_h

echo "[INFO] Discovering and deleting network namespaces and associated veth pairs..."
# List all network namespaces
for NS_NAME in $(ip netns list | awk '{print $1}'); do
    # Check if the namespace name matches our typical pattern (e.g., ends with _ns)
    if [[ "$NS_NAME" == *_ns ]]; then
        VRF_NAME_FROM_NS=$(echo "$NS_NAME" | sed 's/_ns$//') # Extract potential VRF name

        # Construct potential veth host name
        VETH_HOST="veth_${VRF_NAME_FROM_NS}_h"

        echo "[INFO] Processing namespace: $NS_NAME"

        # Delete the host-side veth interface (this also deletes the pair)
        if ip link show "$VETH_HOST" > /dev/null 2>&1; then
            echo "[INFO] Deleting veth interface: $VETH_HOST"
            sudo ip link del "$VETH_HOST"
        else
            echo "[INFO] Veth interface $VETH_HOST not found for $NS_NAME."
        fi

        # Delete the network namespace
        echo "[INFO] Deleting network namespace: $NS_NAME"
        sudo ip netns del "$NS_NAME"
    fi
done

# 3. (Optional) Delete VRF devices
# This is often not desired if VRFs are pre-configured infrastructure.
# Only uncomment if you are sure you want to delete the VRF devices themselves.
# This part will only delete VRFs matching the VRF_NAME_PATTERN.
#
# echo "[INFO] Discovering and deleting VRF devices matching pattern '$VRF_NAME_PATTERN'..."
# for VRF_DEVICE in $(ip link show type vrf | grep -oP '^\d+:\s+\K[^@:]+(?=@NO-CARRIER|\s)"); do
# if [[ "$VRF_DEVICE" == $VRF_NAME_PATTERN* ]]; then
# if ip link show "$VRF_DEVICE" > /dev/null 2>&1; then
# echo "[INFO] Deleting VRF device: $VRF_DEVICE"
# sudo ip link del "$VRF_DEVICE"
# else
# echo "[INFO] VRF device $VRF_DEVICE not found (already deleted?)."
# fi
# fi
# done

# 4. (Optional) Clean up generated Kea config files from orchestrator's default location
ORCHESTRATOR_KEA_CONFIG_DIR="../config" # Path relative to where orchestrator might be run from build/
if [ -d "$ORCHESTRATOR_KEA_CONFIG_DIR" ]; then
    echo "[INFO] Cleaning up generated Kea config files from $ORCHESTRATOR_KEA_CONFIG_DIR..."
    # Example: kea-dhcp4-vrf-red.conf
    sudo find "$ORCHESTRATOR_KEA_CONFIG_DIR" -name "kea-dhcp4-*.conf" -type f -print -delete
    sudo find "$ORCHESTRATOR_KEA_CONFIG_DIR" -name "kea-dhcp6-*.conf" -type f -print -delete
else
    echo "[INFO] Orchestrator Kea config directory $ORCHESTRATOR_KEA_CONFIG_DIR not found, skipping config cleanup."
fi


echo "--- Cleanup Process Complete ---"
echo "Note: VRF devices themselves might not be deleted by default. Manual check:"
echo "  ip link show type vrf"
echo "If any interfaces were associated with VRFs, they might need to be manually reset if the VRF was deleted."
echo "  Example: sudo ip link set dev eth10 master default"
echo "  (or remove 'master <vrf_name>' configuration from the interface)"

chmod +x kea-vrf-orchestrator/scripts/cleanup.sh
