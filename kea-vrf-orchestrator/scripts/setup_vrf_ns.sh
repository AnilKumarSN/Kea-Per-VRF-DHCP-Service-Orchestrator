#!/bin/bash
# Helper script to manually set up a VRF, its namespace, veth pair, and Kea.

set -e # Exit immediately if a command exits with a non-zero status.
# set -x # Print commands and their arguments as they are executed.

DEFAULT_VRF_NAME="vrf-blue"
VRF_NAME="${1:-$DEFAULT_VRF_NAME}"
VRF_TABLE_ID="${2:-1001}" # Route table ID for the VRF
NS_NAME="${VRF_NAME}_ns"
VETH_HOST="veth_${VRF_NAME}_h"
VETH_NS="veth_${VRF_NAME}_ns"
VETH_HOST_IP_CIDR="169.254.100.1/30" # Example IP, ensure it's unique per VRF if running multiple manually
VETH_NS_IP_CIDR="169.254.100.2/30"   # Example IP
CLIENT_IFACE="${3}" # Optional: physical interface to associate with VRF

echo "--- Setting up VRF: $VRF_NAME ---"

# 0. Cleanup previous conflicting devices (optional, for idempotency)
echo "[INFO] Performing pre-cleanup..."
ip link del "$VETH_HOST" 2>/dev/null || true
ip netns del "$NS_NAME" 2>/dev/null || true
# We don't delete the VRF device itself here, as it might be pre-configured.
# If you want to delete the VRF device: sudo ip link del $VRF_NAME 2>/dev/null || true

# 1. Create VRF device (if it doesn't exist)
if ! ip link show "$VRF_NAME" > /dev/null 2>&1; then
    echo "[INFO] Creating VRF device: $VRF_NAME with table $VRF_TABLE_ID"
    sudo ip link add "$VRF_NAME" type vrf table "$VRF_TABLE_ID"
    sudo ip link set dev "$VRF_NAME" up
else
    echo "[INFO] VRF device $VRF_NAME already exists."
fi

# 2. Create Network Namespace
echo "[INFO] Creating network namespace: $NS_NAME"
sudo ip netns add "$NS_NAME"

# 3. Create veth pair
echo "[INFO] Creating veth pair: $VETH_HOST <--> $VETH_NS"
sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"

# 4. Move $VETH_NS to the namespace
echo "[INFO] Moving $VETH_NS to namespace $NS_NAME"
sudo ip link set "$VETH_NS" netns "$NS_NAME"

# 5. Configure IP for host-side veth and bring it up
echo "[INFO] Configuring IP $VETH_HOST_IP_CIDR for $VETH_HOST and bringing it up"
sudo ip addr add "$VETH_HOST_IP_CIDR" dev "$VETH_HOST"
sudo ip link set "$VETH_HOST" up

# 6. Configure IP for namespace-side veth and bring it up
echo "[INFO] Configuring IP $VETH_NS_IP_CIDR for $VETH_NS in $NS_NAME and bringing it up"
sudo ip netns exec "$NS_NAME" ip addr add "$VETH_NS_IP_CIDR" dev "$VETH_NS"
sudo ip netns exec "$NS_NAME" ip link set "$VETH_NS" up

# 7. Bring up loopback interface in the namespace
echo "[INFO] Bringing up loopback interface in $NS_NAME"
sudo ip netns exec "$NS_NAME" ip link set lo up

# 8. Add route in namespace for DHCP server to reply (optional, Kea might handle binding correctly)
# This tells Kea how to send packets back to the orchestrator/veth host end.
# The veth link is point-to-point, so this might be implicit.
VETH_HOST_IP=$(echo $VETH_HOST_IP_CIDR | cut -d'/' -f1)
echo "[INFO] Adding route in $NS_NAME to reach $VETH_HOST_IP via $VETH_NS"
sudo ip netns exec "$NS_NAME" ip route add "$VETH_HOST_IP" dev "$VETH_NS"

# 9. (Optional) Associate a physical interface with the VRF
if [ -n "$CLIENT_IFACE" ]; then
    if ip link show "$CLIENT_IFACE" > /dev/null 2>&1; then
        echo "[INFO] Associating interface $CLIENT_IFACE with VRF $VRF_NAME"
        sudo ip link set dev "$CLIENT_IFACE" master "$VRF_NAME" # For newer kernels
        # Or sudo ip link set dev $CLIENT_IFACE vrf $VRF_NAME # For older kernels
        sudo ip link set dev "$CLIENT_IFACE" up
        echo "[INFO] Ensure $CLIENT_IFACE has an IP or is configured for DHCP client mode."
    else
        echo "[WARN] Client interface $CLIENT_IFACE not found. Skipping association."
    fi
else
    echo "[INFO] No client interface specified for VRF association."
fi

echo "--- VRF $VRF_NAME and Namespace $NS_NAME setup complete ---"
echo "Host side veth: $VETH_HOST ($VETH_HOST_IP_CIDR)"
echo "Namespace side veth: $VETH_NS ($VETH_NS_IP_CIDR) inside $NS_NAME"
echo "To run Kea (example DHCPv4):"
echo "  sudo ip netns exec $NS_NAME kea-dhcp4 -c /path/to/kea-dhcp4-$VRF_NAME.conf"
echo "To enter namespace shell:"
echo "  sudo ip netns exec $NS_NAME bash"
echo "To clean up:"
echo "  sudo ip netns del $NS_NAME"
echo "  sudo ip link del $VETH_HOST"
echo "  sudo ip link del $VRF_NAME" # If you created it here
chmod +x kea-vrf-orchestrator/scripts/setup_vrf_ns.sh
