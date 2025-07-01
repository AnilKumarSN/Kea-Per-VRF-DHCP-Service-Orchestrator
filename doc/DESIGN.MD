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
    *   **Configuration of Client-Facing Interfaces:**
        *   The orchestrator accepts command-line arguments (`-m <if_name>:<vrf_name>:<if_ip>`) to map client-facing network interfaces (identified by `if_name`) to target VRF names. The `if_ip` is the IP address of the orchestrator on that client-facing segment.
        *   These mappings are stored in an `if_vrf_map_t` structure, which also holds the listening socket FD for that interface and the resolved index of the target VRF instance.
    *   **Runtime Dispatching (Targeted Multi-VRF DHCPv4 Relay):**
        *   The `listen_and_dispatch_packets()` function implements the targeted DHCPv4 relay.
        *   **Per-Interface Client Packet Listeners:** For each mapping provided via command-line, a dedicated UDP socket (`if_vrf_map_t.listen_fd`) is created. This socket is bound to the specified `if_ip` for that interface and the DHCP server port (67), with `SO_BROADCAST` enabled.
        *   **Kea Communication Sockets:** For each managed VRF, a dedicated UDP socket (`vrf_instance_t.kea_comm_fd`) is created and bound to its host-side veth IP (e.g., `169.254.x.1:67`).
        *   **I/O Multiplexing:** Uses `select()` to monitor all active per-interface client listener sockets, all active `kea_comm_fd`s, and the `netlink_fd`.
        *   **Packet Processing (Client to Kea):**
            *   When a DHCP BOOTREQUEST is received on a specific per-interface client listener socket:
                *   The orchestrator identifies the `if_vrf_map_t` entry associated with the receiving socket.
                *   It uses the `vrf_name` (or resolved `vrf_idx`) from the mapping to find the target `vrf_instance_t`.
                *   The `giaddr` field in the DHCP packet is set to the `if_ip` of the receiving client-facing interface (from `if_vrf_map_t.if_ip`).
                *   The packet is sent via the target VRF's `kea_comm_fd` to the Kea instance's IP (`veth_ns_ip`) on port 67.
        *   **Packet Processing (Kea to Client):**
            *   When a DHCP BOOTREPLY is received on a VRF's `kea_comm_fd`:
                *   The orchestrator determines which `if_vrf_map_t` entry corresponds to this VRF (assuming a VRF is mapped from at most one client interface for relay replies, or using other correlation if needed).
                *   The reply packet is sent using `sendmsg` via the client-facing socket (`if_vrf_map_t.listen_fd`) of the original ingress interface.
                *   `IP_PKTINFO` is used with `sendmsg` to set the source IP of the reply packet to the `if_ip` of that client-facing interface, ensuring it appears to originate from the correct segment.
                *   The destination is typically broadcast or unicast to `yiaddr` based on packet flags and content.
*   **Linux Network Namespace:** Provides network stack isolation for each Kea instance. Managed via `ip netns` commands.
*   **veth Pair:** Enables IP communication between the Orchestrator (root namespace) and Kea instances (VRF namespaces).
*   **Netlink Socket:** Used by the Orchestrator to receive real-time notifications about network interface additions/deletions, enabling dynamic VRF management.
*   **Kea Server Instance:** Standard Kea binaries running in their respective namespaces, configured by the Orchestrator.

## 3. Packet Flow (Example - DHCPDISCOVER for IPv4 with Targeted Multi-VRF Relay)

Assumptions:
*   Orchestrator started with mapping: `-m eth_client_A:vrf-red:192.168.10.1`
*   Client is on the network segment connected to `eth_client_A`.

1.  **Client Broadcast:** A DHCP client sends a DHCPDISCOVER broadcast on its local network segment (connected to `eth_client_A`).
2.  **Ingress to Orchestrator:** The Orchestrator's per-interface listening socket for `eth_client_A` (bound to `192.168.10.1:67`) receives this broadcast.
3.  **VRF Determination & `giaddr` Setting:**
    *   The Orchestrator identifies that the packet arrived on the socket associated with `eth_client_A`.
    *   From its internal mapping, it determines `eth_client_A` is mapped to `vrf-red`.
    *   It finds the active `vrf_instance_t` for `vrf-red`.
    *   It sets the `giaddr` field of the DHCPDISCOVER packet to `192.168.10.1` (the IP of `eth_client_A`).
4.  **Forward to Kea:** The Orchestrator sends the modified DHCPDISCOVER packet via `vrf-red`'s `kea_comm_fd` to the IP address of the Kea instance's veth interface inside `vrf-red_ns` (e.g., to `169.254.1.2:67`).
5.  **Kea Processing:** The `vrf-red` Kea instance receives the packet. It processes the request (noting `giaddr = 192.168.10.1`), selects an IP, and prepares a DHCPOFFER. Kea unicasts the DHCPOFFER to the `giaddr` (`192.168.10.1:67`).
6.  **Kea Reply to Orchestrator:** The DHCPOFFER travels from Kea's namespace via its veth pair, destined for `192.168.10.1:67`. Since the orchestrator's `kea_comm_fd` for `vrf-red` is bound to `vrf-red`'s `veth_host_ip` (e.g., `169.254.1.1:67`), the kernel routes the packet from Kea (source `169.254.1.2`) to the orchestrator on this socket.
    *Note: Kea sending to `giaddr` which is on a different subnet than its own direct interface requires proper routing. The `veth_host_ip` is the actual IP Kea replies to if `giaddr` is set to `veth_host_ip`. If `giaddr` is set to the client-facing interface IP, Kea sends to that IP. The orchestrator listens on `veth_host_ip` for Kea's replies.*
    **Correction to flow:** Kea sends its reply to the `giaddr`. The orchestrator's `kea_comm_fd` (bound to `veth_host_ip`) is *not* where Kea sends the reply if `giaddr` is the client-facing IF IP. The orchestrator must listen on the `giaddr` for replies, or Kea must send to the relay's IP on the segment from which request originated.
    **Revised Flow Point 6 & 7 (Simpler Model where Kea replies to `veth_host_ip` as `giaddr`):**
    *   If `giaddr` was set to `target_vrf->veth_host_ip` (e.g., `169.254.1.1`):
        6.  **Kea Reply to Orchestrator's Veth:** Kea sends DHCPOFFER to `giaddr` (`169.254.1.1:67`). This is received on `vrf-red`'s `kea_comm_fd`.
        7.  **Orchestrator Receives Reply:** The `select()` loop detects activity on `kea_comm_fd`.
    *(The implemented code sets `giaddr` to the client-facing interface IP. This means Kea's reply will be sent to that IP. The orchestrator's `kea_comm_fd` is bound to its internal veth IP, and is used for *sending to Kea*. For receiving Kea's reply directed to the `giaddr` (client interface IP), the *client-facing listener socket itself* would receive it if that socket were also listening for packets from Kea. This part of the flow needs refinement in implementation or description if `giaddr` is the client-facing IP.)*
    **Let's assume for the design doc that `giaddr` is the client-facing interface IP, and Kea's reply is routed towards that IP. The orchestrator then needs to capture this reply. A simple way is if Kea sends the reply back to the source IP of the packet it received (the `veth_host_ip` from the orchestrator), if `giaddr` is from a different network. The current implementation uses the `kea_comm_fd` (bound to `veth_host_ip`) to receive from Kea.**

7.  **Orchestrator Receives Reply (on `kea_comm_fd`):** The `select()` loop detects activity on `vrf-red`'s `kea_comm_fd`. The orchestrator receives the DHCPOFFER.
8.  **Forward to Client:** The Orchestrator identifies the original ingress interface (`eth_client_A`). It uses `sendmsg` with `IP_PKTINFO` to send the DHCPOFFER:
    *   Destination: Broadcast (or unicast to `yiaddr` if appropriate) on DHCP client port 68.
    *   Source IP: Set to `192.168.10.1` (IP of `eth_client_A`).
    *   Outgoing socket: The listening socket for `eth_client_A`.

## 4. Key Design Decisions & Considerations

*   **Configuration of Mappings:** Client-facing interface to VRF mappings (including the interface's IP for `giaddr` and reply source) are provided via command-line arguments (`-m if:vrf:ip`). This is simple for startup but not dynamically updatable at runtime without restarting.
*   **Per-Interface Sockets:** Using separate listening sockets for each client-facing interface allows clear association of incoming packets to their ingress interface and thus to the correct VRF mapping. These sockets are bound to specific interface IPs.
*   **`giaddr` Setting:** The `giaddr` is set to the IP address of the client-facing interface on which the request was received. This informs Kea about the client's network segment.
*   **Reply Source IP (`IP_PKTINFO`):** Using `sendmsg` with `IP_PKTINFO` is crucial for ensuring that DHCP replies are sourced from the correct IP address when the orchestrator manages multiple client-facing interfaces with different IPs. This makes the orchestrator appear as a proper relay agent on each segment.
*   **Initial VRF Discovery vs. Dynamic Management:** Unchanged.
*   **Namespace/veth Management:** Unchanged.
*   **Kea Configuration:** Unchanged.
*   **Netlink Message Handling:** Updated to re-resolve `if_vrf_map_t.vrf_idx` if a known VRF is re-added, and invalidate `vrf_idx` if a mapped VRF is deleted.
*   **Error Handling:** Basic.
*   **Concurrency:** Single-threaded.

## 5. Future Enhancements

*   **Dynamic Mapping Configuration:** Allow updating interface-to-VRF mappings at runtime (e.g., via a control socket or config file reload).
*   **DHCPv6 Relay Support.**
*   **Full Netlink Integration for network setup.**
*   **Advanced Kea Configuration Management.**
*   **Orchestrator API/CLI.**
*   **Improved Kea Process Monitoring.**
*   **Metrics and Monitoring.**
*   **Threaded Architecture.**
*   **Refined Kea Reply Handling:** Explore if Kea replies directly to `giaddr` (client-facing IP) can be captured more effectively, perhaps by having the client-facing sockets also listen for unicast replies from Kea, or if a shared "reply from Kea" socket is feasible. The current model relies on Kea sending replies to the source of the relayed packet (the `veth_host_ip` end of the `kea_comm_fd`'s binding). If `giaddr` is different, Kea typically sends to `giaddr`. This interaction needs careful validation. *Self-correction: The current code binds `kea_comm_fd` to `veth_host_ip`. If `giaddr` is set to the client-facing IP, Kea will reply to that `giaddr`. The orchestrator must then receive this on the appropriate client-facing socket or a general DHCP port. The current code for receiving from Kea is on `kea_comm_fd`, implying Kea replies to `veth_host_ip`. This is inconsistent if `giaddr` is the client interface IP. The `giaddr` *should* be the client interface IP. Kea will reply to this `giaddr`. The orchestrator then needs to receive this reply. The simplest is if Kea sends it to port 67 of `giaddr`. The client-facing sockets are listening on port 67. So, the reply from Kea to `giaddr` (client-iface-ip:67) *would* be received by the same socket that heard the client originally. This simplifies things.*

This document will be updated as the design and implementation progress.
*   **Advanced Kea Configuration Management.**
*   **Orchestrator API/CLI:** For control and status.
*   **Improved Kea Process Monitoring and Restart Logic.**
*   **Metrics and Monitoring Hooks.**
*   **Threaded Architecture:** For improved performance and responsiveness if needed.

This document will be updated as the design and implementation progress.
