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
*   **Basic DHCPv4 Relay:**
    *   The orchestrator can relay DHCPv4 packets between a client network and Kea instances.
    *   Listens for client DHCP broadcasts on `INADDR_ANY` (port 67).
    *   Forwards requests to the appropriate Kea instance (currently limited to the *first managed VRF*) after setting the `giaddr`.
    *   Relays replies from Kea back to the client network (broadcast on port 68).

## Current Limitations

*   **Single VRF Relay Target:** The DHCP relay logic currently forwards all client requests to the Kea instance of the first detected/managed VRF (`vrf_instances[0]`). It does not yet map clients to specific VRFs based on, for example, the client's ingress interface.
*   **DHCPv6 Support:** While Kea DHCPv6 templates exist, the orchestrator's C code primarily focuses on DHCPv4 setup, relay, and Kea instance management.
*   **Error Handling:** Error handling and recovery mechanisms can be further enhanced.
*   **Configuration:** Orchestrator behavior (like client interface bindings for relay) is not yet configurable via an external file.

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

**Running (example):**
```bash
sudo ./build/orchestrator
```

Refer to `doc/USER_GUIDE.md` for more detailed instructions.
