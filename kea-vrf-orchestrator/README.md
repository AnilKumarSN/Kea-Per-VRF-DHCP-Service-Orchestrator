# Kea Per-VRF DHCP Service Orchestrator

## Overview

This project provides a DHCP service orchestrator designed to manage multiple Kea DHCP server instances, each dedicated to a specific VRF (Virtual Routing and Forwarding) domain on a Linux system. This allows for isolated DHCP services for different network segments or tenants.

The system consists of a central C-based orchestrator application that leverages Linux network namespaces, veth pairs, Netlink sockets, and POSIX threads to achieve its goals. It now operates with a multi-threaded architecture for improved responsiveness and task separation.

## Core Features

*   **Multi-Threaded Architecture:**
    *   **Main Thread:** Handles initialization, signal management (SIGINT, SIGTERM, SIGHUP), thread creation, configuration reloads (triggered by SIGHUP), and graceful shutdown.
    *   **Packet Dispatching Thread:** Manages a `select()` loop for all DHCP packet I/O (client-facing listeners and Kea communication sockets), performing the relay logic. It's notified of configuration changes via a pipe.
    *   **Netlink Monitoring Thread:** Dedicated to listening for VRF interface additions/deletions via Netlink. Updates shared VRF data structures (thread-safe) and signals the dispatch thread.
*   **Dynamic VRF Discovery & Management:**
    *   Discovers existing VRF interfaces at startup.
    *   Utilizes Netlink (`RTMGRP_LINK`) in a dedicated thread to dynamically detect VRF interface changes at runtime.
    *   Automatically sets up/tears down namespaces, veth pairs, and Kea instances for VRFs.
*   **Namespace Isolation:** Creates a dedicated Linux network namespace for each managed VRF.
*   **Kea Instance Management:** Launches and manages Kea DHCPv4 server instances. Basic Kea process status monitoring is included.
*   **Targeted Multi-VRF DHCPv4 Relay with Dynamic Mapping Configuration:**
    *   Relays DHCPv4 packets from specified client-facing network interfaces to their mapped VRF's Kea instance.
    *   **Configuration:**
        *   Interface-to-VRF mappings are primarily loaded from a configuration file (`-c <filepath>`).
        *   Fallback to command-line `-m <map_string>` arguments if no config file is given.
        *   **SIGHUP Reload:** Mappings can be reloaded from the config file at runtime by sending `SIGHUP` to the orchestrator.
    *   Creates dedicated listening sockets for each client-facing interface.
    *   Correctly sets `giaddr` and uses `sendmsg` with `IP_PKTINFO` for replies.

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
