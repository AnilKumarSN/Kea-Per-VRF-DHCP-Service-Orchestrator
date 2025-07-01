#!/bin/bash
# Test script to simulate a DHCP client requesting an IP from a Kea server
# running in a VRF-specific namespace.
#
# CURRENT SCOPE:
# This script primarily tests the ability of a Kea instance, running in its own
# namespace and configured by the orchestrator (or manually), to serve DHCP leases
# to a client that is directly connected to the VRF network segment.
# It achieves this by creating a client namespace and a veth pair where one end
# is in the client namespace and the other end is enslaved to the target VRF.
#
# LIMITATION FOR TESTING ORCHESTRATOR'S ACTIVE RELAY:
# This script, in its current form, DOES NOT directly test the orchestrator's
# active DHCP relay functionality (i.e., the C code listening on `client_listen_fd`
# and forwarding packets). This is because the client's veth (`CLIENT_VETH_TO_VRF`)
# is put directly into the VRF, so packets flow via kernel routing to Kea's veth,
# bypassing the orchestrator's main relay socket.
#
# TO TEST THE ORCHESTRATOR'S ACTIVE RELAY:
# You would need a different setup:
# 1. Orchestrator running and its `client_listen_fd` listening on an interface
#    (e.g., a bridge `br-clients` or a physical interface `ethX`) in the root namespace.
# 2. A DHCP client (e.g., in a VM, another physical machine, or a namespace) connected
#    to that same network segment (e.g., `br-clients` or `ethX`).
# 3. The orchestrator's relay logic would then pick up the client's broadcast from
#    `client_listen_fd` and relay it to the target Kea instance (currently vrf_instances[0]).
#
# Example for testing active relay (conceptual):
#   - Create a bridge in root ns: `sudo ip link add name br-clients type bridge && sudo ip link set br-clients up`
#   - Ensure orchestrator's `client_listen_fd` can receive broadcasts from `br-clients`.
#     (Binding to INADDR_ANY usually suffices if `br-clients` has an IP or is part of routing).
#   - In this script, instead of `sudo ip link set "$CLIENT_VETH_TO_VRF" master "$VRF_NAME"`,
#     you would do `sudo ip link set "$CLIENT_VETH_TO_VRF" master br-clients` (or just bring it up
#     if `br-clients` is the general client network and the orchestrator listens there).
#   - This setup change is NOT implemented in this script by default.

set -e
# set -x # Uncomment for debugging

# --- Configuration ---
VRF_NAME="${1:-vrf-red}" # The VRF your Kea server is serving
CLIENT_NS_NAME="dhcp-client-ns"
CLIENT_VETH_TO_NS="v_client_ns" # veth end inside client namespace
CLIENT_VETH_TO_VRF="v_client_vrf" # veth end connected to VRF (in root ns)
DHCLIENT_TIMEOUT=15 # seconds
DHCP_CLIENT_COMMAND="dhclient" # or "udhcpc -i $CLIENT_VETH_TO_NS -t 5 -T 3 -A 5" or similar

# --- Helper Functions ---
cleanup() {
    echo "[INFO] Cleaning up client test environment..."
    sudo ip netns del "$CLIENT_NS_NAME" 2>/dev/null || true
    sudo ip link del "$CLIENT_VETH_TO_VRF" 2>/dev/null || true
    # Remove any lingering dhclient leases or pids for this interface if necessary
    # Example: sudo rm -f /var/lib/dhcp/dhclient."$CLIENT_VETH_TO_NS".leases
    echo "[INFO] Client test cleanup complete."
}

trap cleanup EXIT SIGINT SIGTERM

# --- Main Test Logic ---

echo "--- DHCP Client Test for VRF: $VRF_NAME ---"

# 0. Pre-requisite check: Ensure the target VRF device exists
if ! ip link show "$VRF_NAME" type vrf > /dev/null 2>&1; then
    echo "[ERROR] VRF device '$VRF_NAME' not found. Please set it up first."
    echo "You might need to run something like: sudo ./scripts/setup_vrf_ns.sh $VRF_NAME <table_id>"
    echo "And ensure Kea is running for this VRF, e.g. via the orchestrator or ./scripts/start_kea_in_ns.sh"
    exit 1
fi
echo "[INFO] Target VRF '$VRF_NAME' found."

# 1. Perform cleanup from any previous run
cleanup
echo "[INFO] Previous client test environment cleaned up."

# 2. Create a client network namespace
echo "[INFO] Creating client network namespace: $CLIENT_NS_NAME"
sudo ip netns add "$CLIENT_NS_NAME"

# 3. Create a veth pair for the client
echo "[INFO] Creating veth pair: $CLIENT_VETH_TO_NS (in $CLIENT_NS_NAME) <--> $CLIENT_VETH_TO_VRF (in root)"
sudo ip link add "$CLIENT_VETH_TO_NS" type veth peer name "$CLIENT_VETH_TO_VRF"

# 4. Move one end of the veth pair into the client namespace
echo "[INFO] Moving $CLIENT_VETH_TO_NS to namespace $CLIENT_NS_NAME"
sudo ip link set "$CLIENT_VETH_TO_NS" netns "$CLIENT_NS_NAME"

# 5. Assign the other end of the veth pair to the target VRF in the root namespace
echo "[INFO] Assigning $CLIENT_VETH_TO_VRF to VRF $VRF_NAME"
sudo ip link set "$CLIENT_VETH_TO_VRF" master "$VRF_NAME"
# For older kernels, it might be: sudo ip link set dev $CLIENT_VETH_TO_VRF vrf $VRF_NAME

# 6. Bring up interfaces
echo "[INFO] Bringing up interface $CLIENT_VETH_TO_VRF in root namespace"
sudo ip link set "$CLIENT_VETH_TO_VRF" up

echo "[INFO] Bringing up interface $CLIENT_VETH_TO_NS in $CLIENT_NS_NAME"
sudo ip netns exec "$CLIENT_NS_NAME" ip link set "$CLIENT_VETH_TO_NS" up

echo "[INFO] Bringing up loopback interface in $CLIENT_NS_NAME"
sudo ip netns exec "$CLIENT_NS_NAME" ip link set lo up

# Allow a moment for interfaces and VRF associations to settle
sleep 2

echo "[INFO] Interfaces and VRF association:"
echo "Root Namespace:"
ip link show "$CLIENT_VETH_TO_VRF"
echo "Client Namespace ($CLIENT_NS_NAME):"
sudo ip netns exec "$CLIENT_NS_NAME" ip link show "$CLIENT_VETH_TO_NS"

# 7. Run DHCP client in the client namespace
echo "[INFO] Attempting to obtain DHCP lease in $CLIENT_NS_NAME on interface $CLIENT_VETH_TO_NS..."
echo "[INFO] Using command: sudo ip netns exec $CLIENT_NS_NAME $DHCP_CLIENT_COMMAND -v -1 -d --no-pid -lf /tmp/dhclient-$CLIENT_VETH_TO_NS.leases $CLIENT_VETH_TO_NS"

# For dhclient:
# -v: verbose
# -1: try once then exit (optional, but good for scripting)
# -d: force foreground
# --no-pid: don't write pid file
# -lf: lease file path
#
# For udhcpc:
# -i interface
# -f run in foreground
# -n exit if lease is not obtained
# -q exit after obtaining lease
# -t retries
# -T seconds between retries
# -A seconds to wait for lease offer
# (udhcpc options can vary by build)

# Create an empty lease file first to avoid dhclient errors if it can't create it
sudo ip netns exec "$CLIENT_NS_NAME" touch "/tmp/dhclient-$CLIENT_VETH_TO_NS.leases"

# Execute dhclient with a timeout
# The actual command might need adjustment based on the specific dhclient version and desired behavior.
# Some versions of dhclient fork to background even with -d, so checking IP is more reliable.
sudo ip netns exec "$CLIENT_NS_NAME" timeout "$DHCLIENT_TIMEOUT" "$DHCP_CLIENT_COMMAND" \
    -v \
    "$([ "$DHCP_CLIENT_COMMAND" == "dhclient" ] && echo "-1")" \
    "$([ "$DHCP_CLIENT_COMMAND" == "dhclient" ] && echo "-d")" \
    "$([ "$DHCP_CLIENT_COMMAND" == "dhclient" ] && echo "--no-pid")" \
    "$([ "$DHCP_CLIENT_COMMAND" == "dhclient" ] && echo "-lf /tmp/dhclient-$CLIENT_VETH_TO_NS.leases")" \
    "$([ "$DHCP_CLIENT_COMMAND" == "udhcpc" ] && echo "-i")" \
    "$CLIENT_VETH_TO_NS" \
    "$([ "$DHCP_CLIENT_COMMAND" == "udhcpc" ] && echo "-f -n -q -t 3 -T 2")"

DHCP_EXIT_CODE=$?

if [ $DHCP_EXIT_CODE -eq 124 ]; then # Timeout exit code
    echo "[FAIL] DHCP client timed out after $DHCLIENT_TIMEOUT seconds."
    exit 1
elif [ $DHCP_EXIT_CODE -ne 0 ]; then
    echo "[WARN] DHCP client exited with code $DHCP_EXIT_CODE. This might be okay if an IP was obtained before exiting (e.g. with -1)."
fi

# 8. Check if an IP address was obtained in the client namespace
echo "[INFO] Checking for IP address on $CLIENT_VETH_TO_NS in $CLIENT_NS_NAME..."
CLIENT_IP=$(sudo ip netns exec "$CLIENT_NS_NAME" ip addr show dev "$CLIENT_VETH_TO_NS" | grep -w inet | awk '{print $2}' | cut -d'/' -f1)

if [ -n "$CLIENT_IP" ]; then
    echo "[SUCCESS] DHCP client in $CLIENT_NS_NAME obtained IP: $CLIENT_IP on interface $CLIENT_VETH_TO_NS"
    echo "[INFO] Lease file content (/tmp/dhclient-$CLIENT_VETH_TO_NS.leases in $CLIENT_NS_NAME):"
    sudo ip netns exec "$CLIENT_NS_NAME" cat "/tmp/dhclient-$CLIENT_VETH_TO_NS.leases" || echo "(Lease file not found or empty)"
    # Release the lease (optional, good practice)
    # sudo ip netns exec "$CLIENT_NS_NAME" dhclient -r "$CLIENT_VETH_TO_NS" -lf /tmp/dhclient-$CLIENT_VETH_TO_NS.leases || true
else
    echo "[FAIL] DHCP client in $CLIENT_NS_NAME did NOT obtain an IP address on interface $CLIENT_VETH_TO_NS."
    echo "[INFO] Kea server logs (check VRF-specific logs in /var/log/kea/ or syslog) and orchestrator logs might have more details."
    exit 1
fi

echo "--- DHCP Client Test for VRF: $VRF_NAME COMPLETE ---"
# Cleanup will be handled by trap

chmod +x kea-vrf-orchestrator/tests/run_dhcp_client_test.sh
