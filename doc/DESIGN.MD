# Kea Per-VRF DHCP Service Orchestrator - Design Document

## 1. Overview

The Kea Per-VRF DHCP Service Orchestrator is a system designed to provide DHCP services in a multi-VRF (Virtual Routing and Forwarding) environment. It manages multiple instances of the Kea DHCP server, with each instance operating in an isolated Linux network namespace corresponding to a specific VRF. This ensures that DHCP services for one VRF do not interfere with another.

The system is composed of a central C-based Orchestrator application, standard Kea DHCP server binaries, and leverages Linux kernel features like network namespaces, veth pairs, and Netlink sockets for isolation, communication, and dynamic updates.

## 2. System Architecture

*   **Orchestrator (Core C Application):**
    *   Runs in the host's root network namespace.
    *   **VRF Discovery & Management:**
        *   **Initial Discovery:** At startup, parses `ip link show type vrf` output to discover pre-existing VRFs.
        *   **Dynamic Runtime Management (Netlink):**
            *   Opens a Netlink socket (`NETLINK_ROUTE`) and subscribes to `RTMGRP_LINK` messages.
            *   Listens for `RTM_NEWLINK` and `RTM_DELLINK` messages concerning interfaces of type "vrf".
            *   Dynamically adds newly created VRFs: sets up their namespace, veth pair, Kea instance, and communication sockets.
            *   Dynamically removes deleted VRFs: cleans up all associated resources (Kea process, namespace, veth, sockets).
    *   **Lifecycle Management (per VRF):**
        *   Creates a dedicated network namespace (e.g., `vrf-red_ns`).
        *   Creates a veth pair: one end in the root namespace (`v<name>_h`), the other moved into the VRF's namespace (`v<name>_ns`).
        *   Assigns IP addresses from a private range (e.g., `169.254.x.x/30`) to both ends of the veth pair.
        *   Launches Kea DHCPv4 (`kea-dhcp4`) process inside the namespace using `ip netns exec`.
        *   Generates Kea configuration files from a template (`config/kea-dhcp4-template.conf`), ensuring Kea binds to the veth interface within its namespace and uses VRF-specific log/lease files.
    *   **Runtime Dispatching (Basic DHCPv4 Relay):**
        *   The `listen_and_dispatch_packets()` function implements a basic DHCPv4 relay.
        *   **Client Packet Listener:** A single UDP socket (`client_listen_fd`) binds to `INADDR_ANY` and DHCP server port (67) with `SO_BROADCAST` enabled to receive DHCP requests from clients.
        *   **Kea Communication Sockets:** For each managed VRF, a dedicated UDP socket (`kea_comm_fd`) is created and bound to the host-side veth IP (e.g., `169.254.x.1:67`). This socket is used to send requests to and receive replies from its corresponding Kea instance.
        *   **I/O Multiplexing:** Uses `select()` to monitor `client_listen_fd`, all active `kea_comm_fd`s, and the `netlink_fd`.
        *   **Packet Processing (Client to Kea):**
            *   When a DHCP BOOTREQUEST is received on `client_listen_fd`:
                *   **Limitation:** Currently, the request is forwarded to the Kea instance of the *first* managed VRF (`vrf_instances[0]`).
                *   The `giaddr` field in the DHCP packet is set to the `veth_host_ip` of the target VRF.
                *   The packet is sent via the target VRF's `kea_comm_fd` to the Kea instance's IP (`veth_ns_ip`) on port 67.
        *   **Packet Processing (Kea to Client):**
            *   When a DHCP BOOTREPLY is received on a VRF's `kea_comm_fd`:
                *   The packet is broadcast via `client_listen_fd` to the DHCP client port (68) on the client network(s).
*   **Linux Network Namespace:** Provides network stack isolation for each Kea instance. Managed via `ip netns` commands.
*   **veth Pair:** Enables IP communication between the Orchestrator (root namespace) and Kea instances (VRF namespaces).
*   **Netlink Socket:** Used by the Orchestrator to receive real-time notifications about network interface additions/deletions, enabling dynamic VRF management.
*   **Kea Server Instance:** Standard Kea binaries running in their respective namespaces, configured by the Orchestrator.

## 3. Packet Flow (Example - DHCPDISCOVER for IPv4 with Orchestrator Relay)

1.  **Client Broadcast:** A DHCP client sends a DHCPDISCOVER broadcast on its local network segment.
2.  **Ingress to Orchestrator:** The Orchestrator's `client_listen_fd` (bound to `INADDR_ANY:67`) receives this broadcast.
3.  **VRF Determination & `giaddr`:**
    *   The Orchestrator (currently) selects the first managed VRF (e.g., `vrf_instances[0]`).
    *   It sets the `giaddr` field of the DHCPDISCOVER packet to the `veth_host_ip` of this selected VRF (e.g., `169.254.1.1`).
4.  **Forward to Kea:** The Orchestrator sends the modified DHCPDISCOVER packet via the selected VRF's `kea_comm_fd` to the IP address of the Kea instance's veth interface inside its namespace (e.g., to `169.254.1.2:67`).
5.  **Kea Processing:** The target Kea instance receives the packet on its `veth_ns` interface. It processes the request, selects an IP, and prepares a DHCPOFFER. Since `giaddr` is set, Kea unicasts the DHCPOFFER to this `giaddr` (i.e., to `169.254.1.1:67`).
6.  **Kea Reply to Orchestrator:** The DHCPOFFER travels from Kea's namespace via the veth pair to the Orchestrator's `kea_comm_fd` (which is bound to `169.254.1.1:67`).
7.  **Orchestrator Receives Reply:** The Orchestrator's `select()` loop detects activity on the `kea_comm_fd`. It receives the DHCPOFFER.
8.  **Forward to Client:** The Orchestrator broadcasts the DHCPOFFER packet via its `client_listen_fd` to the DHCP client port (68) on the client network(s).

## 4. Key Design Decisions & Considerations

*   **Initial VRF Discovery vs. Dynamic Management:** The system now combines initial discovery at startup (`ip link show type vrf`) with runtime dynamic management using Netlink `RTMGRP_LINK` messages for VRF interfaces.
*   **Namespace/veth Management:** Continues to use `ip` command-line tool via `fork/exec` for simplicity. Direct Netlink syscalls for this remain a future option for more atomicity.
*   **Kea Configuration:** Uses template files (`config/kea-dhcp4-template.conf`) with placeholder replacement.
*   **Packet Dispatching Implementation:**
    *   A basic DHCPv4 relay is implemented.
    *   Uses standard UDP sockets for client listening and Kea communication. `SO_BROADCAST` is enabled on the client listener.
    *   **Current Limitation:** Client requests are relayed only to the first managed VRF instance (`vrf_instances[0]`). A mechanism to map incoming client requests (e.g., based on ingress interface if multiple client-facing interfaces are used, or other criteria) to the correct target VRF is a critical next step for multi-VRF relay functionality.
    *   Replies from Kea are broadcast on the client network. More targeted delivery (unicast to client IP or L2 MAC) could be a future refinement.
*   **Netlink Message Handling:**
    *   Implemented in a single-threaded fashion within the main `select()` loop.
    *   Parses `RTM_NEWLINK` and `RTM_DELLINK` for VRF interface kind.
    *   Manages the `vrf_instances` array by appending new VRFs and shifting elements on deletion.
*   **Error Handling:** Basic error logging is present. More sophisticated error recovery (e.g., for failed Kea starts, socket errors) can be added.
*   **Concurrency:** The current model is single-threaded. Future performance needs might necessitate a multi-threaded approach for packet processing or Netlink handling, which would require careful synchronization.

## 5. Future Enhancements

*   **Targeted Multi-VRF Relay:** Implement logic to map incoming client DHCP requests to the correct VRF instance, rather than just the first one. This could involve:
    *   Allowing configuration of multiple client-facing interfaces, each mapped to a specific VRF.
    *   Using `recvfrom` on sockets bound to specific interfaces or using `IP_PKTINFO` to determine ingress interface.
*   **Robust Kea->Client Forwarding:** Use `IP_PKTINFO` to send replies from the correct source IP if the orchestrator has multiple IPs on client networks. Consider L2 raw sockets for direct MAC-addressed unicast/broadcast.
*   **DHCPv6 Relay Support.**
*   **Full Netlink Integration:** Use Netlink for network setup/teardown instead of `ip` commands.
*   **Advanced Kea Configuration Management.**
*   **Orchestrator API/CLI:** For control and status.
*   **Improved Kea Process Monitoring and Restart Logic.**
*   **Metrics and Monitoring Hooks.**
*   **Threaded Architecture:** For improved performance and responsiveness if needed.

This document will be updated as the design and implementation progress.
