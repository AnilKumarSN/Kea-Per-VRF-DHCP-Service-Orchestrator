# Kea Per-VRF DHCP Service Orchestrator - Design Document

## 1. Overview

The Kea Per-VRF DHCP Service Orchestrator is a system designed to provide DHCP services in a multi-VRF (Virtual Routing and Forwarding) environment. It manages multiple instances of the Kea DHCP server, with each instance operating in an isolated Linux network namespace corresponding to a specific VRF. This ensures that DHCP services for one VRF do not interfere with another.

The system is composed of a central C-based Orchestrator application, standard Kea DHCP server binaries, and leverages Linux kernel features like network namespaces, veth pairs, and Netlink sockets for isolation, communication, and dynamic updates.

## 2. System Architecture

*   **Orchestrator (Core C Application):**
    *   Runs in the host's root network namespace.
    *   **Interface-to-VRF Mappings Configuration:**
        *   **Initial Setup:** Mappings from client-facing network interfaces to VRFs (including the orchestrator's IP on that interface, used as `giaddr` and for sourcing replies) are configured at startup.
            *   This is primarily done via a configuration file (e.g., `orchestrator.conf`) specified with the `-c <filepath>` command-line option. Each line in the file defines a mapping in the format: `<if_name>:<vrf_name>:<if_ip>`. Comments (`#`) and empty lines are ignored. The orchestrator parses this file using `parse_config_file()`.
            *   Alternatively, if no configuration file is specified, mappings can be provided using multiple `-m <if_name>:<vrf_name>:<if_ip>` command-line arguments, parsed by `process_cli_mappings()`. If `-c` is used, any `-m` arguments are ignored for the initial setup.
        *   **Runtime Reload (SIGHUP):** When the orchestrator receives a `SIGHUP` signal (handler `sighup_handler` sets `reload_config_flag`), the `listen_and_dispatch_packets()` loop calls `reload_interface_mappings()`.
            *   `reload_interface_mappings()` re-parses the configuration file.
            *   It compares the new set of mappings against the current active ones by checking `if_name`, `vrf_name`, and `if_ip_str`.
            *   Listening sockets (`if_vrf_map_t.listen_fd`) for mappings that are removed or whose IP addresses have changed are closed.
            *   Sockets for new mappings or those with changed IPs are created (or recreated) using a helper `setup_if_map_socket()`. This helper enables `SO_BROADCAST` and `SO_REUSEADDR`.
            *   Mappings that remain unchanged (same interface, VRF, and IP) retain their existing listening sockets.
            *   The internal `vrf_idx` (linking a map to an active VRF instance) is re-resolved for all current mappings by `resolve_vrf_indices_for_maps()` after the reload and also after dynamic VRF changes.
        *   These mappings are stored internally in a global array `if_vrf_map_t if_vrf_maps[]`.
    *   **VRF Discovery & Management:**
        *   **Initial Discovery:** At startup, `discover_vrfs()` parses `ip link show type vrf` output to discover pre-existing VRFs.
        *   **Dynamic Runtime Management (Netlink):**
            *   A Netlink socket (`netlink_fd`) subscribes to `RTMGRP_LINK` messages.
            *   On `RTM_NEWLINK` for a new VRF interface: the orchestrator sets up its namespace, veth pair, Kea instance (`launch_kea_in_namespace`), and Kea communication socket (`setup_kea_communication_socket`). It then calls `resolve_vrf_indices_for_maps()` to link any relevant configured interface mappings to this newly active VRF.
            *   On `RTM_DELLINK` for a managed VRF interface: the orchestrator cleans up all associated resources (`cleanup_vrf_instance`) and calls `resolve_vrf_indices_for_maps()` to invalidate the `vrf_idx` in any interface mappings that pointed to the removed VRF.
    *   **Lifecycle Management (per VRF):** Involves `setup_namespace_for_vrf`, `launch_kea_in_namespace`, `setup_kea_communication_socket`, and `cleanup_vrf_instance`. Kea configurations are generated from templates (the `launch_kea_in_namespace` function was updated to use `current_vrf_count_for_subnet_logic` which is effectively `num_vrfs` at the time of call, for generating unique subnet examples).
    *   **Runtime Dispatching (Targeted Multi-VRF DHCPv4 Relay):**
        *   The `listen_and_dispatch_packets()` function contains the main `select()` loop.
        *   **Per-Interface Client Packet Listeners:** For each active and valid mapping, a dedicated UDP socket (`if_vrf_map_t.listen_fd`) is bound to the mapping's specified `if_ip` and DHCP server port (67).
        *   **Kea Communication Sockets:** For each managed VRF, a UDP socket (`vrf_instance_t.kea_comm_fd`) is bound to its host-side veth IP and DHCP server port (67).
        *   **I/O Multiplexing:** `select()` monitors all active client listener sockets, Kea communication sockets, and the Netlink socket. The `reload_config_flag` is checked to trigger `reload_interface_mappings()`.
        *   **Packet Processing (Client to Kea):**
            *   When a DHCP BOOTREQUEST is received on a per-interface client listener socket:
                *   The orchestrator uses the `if_vrf_map_t` associated with the socket to identify the target `vrf_instance_t` (via `vrf_idx`).
                *   The `giaddr` field in the DHCP packet is set to the `if_ip` of this client-facing interface.
                *   The packet is sent via the target VRF's `kea_comm_fd` to its Kea instance.
        *   **Packet Processing (Kea to Client):**
            *   When a DHCP BOOTREPLY is received on a VRF's `kea_comm_fd`:
                *   The orchestrator finds the `if_vrf_map_t` entry whose `vrf_idx` matches the replying VRF.
                *   The reply is sent using `sendmsg` via the client-facing socket of that mapping.
                *   `IP_PKTINFO` is used with `sendmsg` to set the source IP of the reply packet to the `if_ip` of that client-facing interface.
*   **Linux Network Namespace:** (Unchanged: provides isolation, managed via `ip netns`).
*   **veth Pair:** (Unchanged: inter-namespace communication link).
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

*   **Configuration of Mappings (Startup and Runtime):**
    *   Interface-to-VRF mappings are primarily managed via a configuration file (`-c <filepath>`). This allows for persistent and manageable configurations. The format is `<if_name>:<vrf_name>:<if_ip>` per line.
    *   Command-line `-m` arguments serve as a fallback if no config file is used for initial setup. If `-c` is specified, `-m` arguments are ignored at startup.
    *   **SIGHUP Reload:** Runtime reloading of mappings from the config file is triggered by `SIGHUP`. The `reload_interface_mappings()` function handles this by parsing the file, comparing with current mappings, and managing listening sockets (closing old/modified, creating new, preserving unchanged). `SO_REUSEADDR` is set on these sockets.
*   **Per-Interface Sockets for Client Traffic:** Dedicated UDP listening sockets are created for each client-facing interface defined in the mappings, bound to the specific IP of that interface.
*   **`giaddr` Setting:** The `giaddr` in relayed DHCP requests is set to the IP of the client-facing interface that received the broadcast.
*   **Reply Source IP (`IP_PKTINFO`):** DHCP replies are sent using `sendmsg` with `IP_PKTINFO` to ensure the source IP is that of the correct client-facing interface.
*   **Dynamic VRF Management (Netlink):** Netlink (`RTMGRP_LINK`) is used to detect VRF additions/deletions. When a VRF's status changes, `resolve_vrf_indices_for_maps()` is called to update the `vrf_idx` in all relevant `if_vrf_map_t` entries, linking or unlinking them from active VRF instances.
*   **Single-Threaded Model with `select()`:** All I/O and event handling (SIGHUP flag, Netlink messages) are managed in a single thread using `select()`.
*   **Error Handling:** Basic. Further enhancements for production robustness are needed.

## 5. Future Enhancements

*   **DHCPv6 Relay Support.**
*   **Full Netlink Integration for network setup/teardown** (replacing `ip` command execution).
*   **Advanced Kea Configuration Management.**
*   **Orchestrator API/CLI.**
*   **Improved Kea Process Monitoring.**
*   **Metrics and Monitoring.**
*   **Threaded Architecture.**
*   **Refined Kea Reply Handling & `giaddr` Strategy:** The current model, where Kea replies to the `giaddr` (client-facing interface IP) and the orchestrator receives this reply on its `kea_comm_fd` (bound to the internal veth IP), relies on the system's routing to direct Kea's reply back through the veth pair to the orchestrator. This should generally work but could be further analyzed for edge cases or alternative approaches (e.g., ensuring Kea always replies to the `veth_host_ip` which then gets forwarded, or having client-facing sockets also prepared to receive unicast replies from Kea if `giaddr` is set to the client-facing IP). The key is that Kea *must* send its reply in a way that the orchestrator can intercept it to then forward to the client with the correct source IP via `IP_PKTINFO`. The current implementation expects Kea's replies on the `kea_comm_fd`.

This document will be updated as the design and implementation progress.
*   **Metrics and Monitoring Hooks.**
*   **Threaded Architecture:** For improved performance and responsiveness if needed.

This document will be updated as the design and implementation progress.
