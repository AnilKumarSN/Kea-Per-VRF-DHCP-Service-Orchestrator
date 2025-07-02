# Kea Per-VRF DHCP Service Orchestrator

## Overview

This project provides a DHCP service orchestrator designed to manage multiple Kea DHCP server instances, each dedicated to a specific VRF (Virtual Routing and Forwarding) domain on a Linux system. This allows for isolated DHCP services for different network segments or tenants.

The system consists of a central C-based orchestrator application that leverages Linux network namespaces, veth pairs, and Netlink sockets to achieve its goals.

## Core Features

*   **Dynamic VRF Discovery & Management:**
    *   Discovers existing VRF interfaces at startup.
    *   Utilizes Netlink (`RTMGRP_LINK`) to dynamically detect VRF interfaces being added or removed at runtime.
    *   Automatically sets up namespaces, veth pairs, and Kea instances for newly added VRFs.
    *   Cleans up resources for VRFs that are removed.
*   **Namespace Isolation:** Creates a dedicated Linux network namespace for each managed VRF, ensuring isolated DHCP services.
*   **Kea Instance Management:** Launches and manages Kea DHCPv4 server instances within these isolated namespaces. Monitors Kea process status (basic).
*   **Inter-Namespace Communication:** Sets up veth pairs for communication between the orchestrator (root namespace) and each Kea instance.
*   **Configuration Generation:** Generates Kea DHCPv4 configuration files from a template (`config/kea-dhcp4-template.conf`), customizing them for each VRF.
*   **Targeted Multi-VRF DHCPv4 Relay with Dynamic Mapping Configuration:**
    *   Relays DHCPv4 packets from specified client-facing network interfaces to their mapped VRF's Kea instance.
    *   **Configuration:**
        *   Interface-to-VRF mappings (`<if_name>:<vrf_name>:<if_ip>`) are primarily loaded from a configuration file specified using the `-c <filepath>` command-line option.
        *   Example line in config file: `eth0:vrf-red:192.168.1.1`
        *   If `-c` is not used, mappings can be provided via multiple `-m <map_string>` arguments as a fallback.
        *   **SIGHUP Reload:** Sending a `SIGHUP` signal to the orchestrator process triggers a reload of mappings from the specified configuration file, allowing for runtime updates (add, remove, modify mappings) without a full restart.
    *   Creates a dedicated listening socket for each mapped client-facing interface, bound to its specified IP.
    *   Sets `giaddr` in DHCP requests to the IP of the ingress client-facing interface.
    *   Uses `sendmsg` with `IP_PKTINFO` for DHCP replies to ensure correct source IP.

## Current Limitations

*   **DHCPv6 Support:** Relay and Kea management logic primarily focuses on DHCPv4.
*   **Error Handling:** While improved, it can be further enhanced for production scenarios.
*   **Advanced Configuration Options:** More complex settings beyond interface mappings are not yet supported in the config file.

## Project Structure

*   `src/`: Orchestrator C source code.
*   `scripts/`: Helper shell scripts for manual setup and cleanup.
*   `config/`: Kea configuration templates.
*   `tests/`: Test scripts.
*   `doc/`: Design documents and user guides.
*   `build/`: Compiled binaries.
*   `Makefile`: For building the project.

## Getting Started (Basic Setup - More details in USER_GUIDE.md)

**Prerequisites:**
*   Linux system with VRF, network namespace, and veth support.
*   `iproute2` utilities.
*   Kea DHCP server binaries installed.
*   GCC and Make.

**Compilation:**
```bash
make
```

**Running:**

To use command-line mappings (fallback if no config file):
```bash
# Example: Map interface eth1 (IP 192.168.1.10) to vrf-red
# and interface eth2 (IP 10.0.0.10) to vrf-blue
sudo ./build/orchestrator \
    -m eth1:vrf-red:192.168.1.10 \
    -m eth2:vrf-blue:10.0.0.10
```

To use a configuration file (recommended):
1.  Create a configuration file (e.g., `orchestrator.conf`):
    ```
    # Interface mappings: if_name:vrf_name:if_ip
    eth1:vrf-red:192.168.1.10
    eth2:vrf-blue:10.0.0.10
    ```
2.  Run the orchestrator:
    ```bash
    sudo ./build/orchestrator -c orchestrator.conf
    ```

**Dynamic Operations:**

*   **Reload Mappings:** Modify your configuration file, then send `SIGHUP` to the orchestrator process:
    ```bash
    sudo kill -SIGHUP $(pidof orchestrator)
    ```
*   **Dynamic VRF Add/Delete:** While the orchestrator is running:
    1.  **Add a new VRF:** `sudo ip link add vrf-green type vrf table 1003 && sudo ip link set dev vrf-green up`
        *   The orchestrator should detect `vrf-green` via Netlink. If a mapping for `vrf-green` exists in its current configuration (loaded via `-c` or `-m`), the relay for that interface will become (or remain) active.
    2.  **Delete an existing VRF:** `sudo ip link del vrf-red`
        *   The orchestrator should detect the deletion and clean up resources. Any mappings to `vrf-red` will become inactive for relay until `vrf-red` is re-added and mappings are re-resolved (either at startup or via SIGHUP if the config still includes it).

Refer to `doc/USER_GUIDE.md` for more detailed instructions on setup, prerequisites, and advanced testing.
