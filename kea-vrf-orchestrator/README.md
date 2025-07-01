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
*   **Targeted Multi-VRF DHCPv4 Relay:**
    *   The orchestrator relays DHCPv4 packets from specified client-facing network interfaces to their mapped VRF's Kea instance.
    *   Client-facing interfaces and their mappings to VRFs (including the interface's IP for `giaddr`) are configured via the `-m <if_name>:<vrf_name>:<if_ip>` command-line argument. Multiple mappings can be specified.
    *   Creates a dedicated listening socket for each mapped client-facing interface, bound to its specified IP and DHCP server port (67).
    *   Sets the `giaddr` in DHCP requests to the IP of the ingress client-facing interface.
    *   Uses `sendmsg` with `IP_PKTINFO` to ensure DHCP replies are sourced from the correct client-facing interface IP, enabling proper operation across multiple network segments.

## Current Limitations

*   **Static Mappings:** Interface-to-VRF mappings are currently provided only at startup via command-line arguments. They cannot be updated dynamically while the orchestrator is running.
*   **DHCPv6 Support:** Relay and Kea management logic primarily focuses on DHCPv4.
*   **Error Handling:** Can be further enhanced for production robustness.
*   **Advanced Configuration:** Lacks a dedicated configuration file for more complex settings beyond command-line arguments.

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

**Running (example with interface mappings):**
```bash
# Example: Map interface eth1 (IP 192.168.1.10) to vrf-red
# and interface eth2 (IP 10.0.0.10) to vrf-blue
sudo ./build/orchestrator \
    -m eth1:vrf-red:192.168.1.10 \
    -m eth2:vrf-blue:10.0.0.10
```

**Testing Dynamic VRF Add/Delete:**
While the orchestrator is running (after initial setup with any `-m` mappings):
1.  **Add a new VRF:** `sudo ip link add vrf-green type vrf table 1003 && sudo ip link set dev vrf-green up`
    *   The orchestrator should detect `vrf-green` via Netlink and set up its namespace and Kea instance. If a `-m` mapping previously specified `vrf-green`, the relay for that interface should now become active.
2.  **Delete an existing VRF:** `sudo ip link del vrf-red`
    *   The orchestrator should detect the deletion, clean up resources for `vrf-red`, and any `-m` mapping for `vrf-red` will become inactive for relay.

Refer to `doc/USER_GUIDE.md` for more detailed instructions on setup, prerequisites, and advanced testing.
