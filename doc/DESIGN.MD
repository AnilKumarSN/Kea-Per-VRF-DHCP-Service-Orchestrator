# Kea Per-VRF DHCP Service Orchestrator - Design Document

## 1. Overview

The Kea Per-VRF DHCP Service Orchestrator is a system designed to provide DHCP services in a multi-VRF (Virtual Routing and Forwarding) environment. It manages multiple instances of the Kea DHCP server, with each instance operating in an isolated Linux network namespace corresponding to a specific VRF. This ensures that DHCP services for one VRF do not interfere with another.

The system is composed of a central C-based Orchestrator application, standard Kea DHCP server binaries, and leverages Linux kernel features like network namespaces, veth pairs, and Netlink sockets for isolation, communication, and dynamic updates.

## 2. System Architecture

The orchestrator is evolving towards a multi-threaded architecture to handle different tasks concurrently and maintain responsiveness.

*   **Main Thread:**
    *   Responsible for overall application initialization:
        *   Parses command-line arguments (including `-c <config_file>` for mappings and fallback `-m <map_string>`).
        *   Loads initial interface-to-VRF mappings from the specified config file (using `parse_config_file`) or command-line arguments (`process_cli_mappings`).
        *   Initializes synchronization primitives: `vrf_list_mutex`, `map_list_mutex`, and `notify_pipe`.
        *   Sets up signal handlers for `SIGINT`, `SIGTERM` (for shutdown) and `SIGHUP` (for config reload).
        *   Discovers pre-existing VRFs (`discover_vrfs`) and sets up their namespaces, Kea instances, and communication sockets (`setup_namespace_for_vrf`, `launch_kea_in_namespace`, `setup_kea_communication_socket`).
        *   Resolves initial `vrf_idx` for all loaded interface mappings (`resolve_vrf_indices_for_maps`).
        *   Creates and binds per-interface client listening sockets (`setup_if_map_socket`).
    *   **Thread Management:**
        *   Spawns the Packet Dispatching Thread and the Netlink Monitoring Thread.
    *   **Runtime Loop:** Enters a loop checking for `global_shutdown_flag` and `reload_config_flag`.
        *   If `reload_config_flag` (set by SIGHUP handler) is true, it calls `reload_interface_mappings()` (which acquires necessary mutexes) and then signals the Packet Dispatching Thread via `notify_pipe` to update its monitored file descriptors.
    *   **Shutdown:** On `global_shutdown_flag`, signals worker threads (e.g., by writing to `notify_pipe` and setting the flag) and waits for them to join using `pthread_join()`. Performs final cleanup of global resources (mutexes, pipe FDs).

*   **Packet Dispatching Thread (`dispatch_thread_func`):**
    *   Contains the primary `select()` loop for I/O multiplexing.
    *   **Monitored FDs:**
        *   All active per-interface client listening sockets (`if_vrf_map_t.listen_fd`).
        *   All active Kea communication sockets (`vrf_instance_t.kea_comm_fd`).
        *   The read end of `notify_pipe` to wake up for configuration changes.
    *   **Configuration Updates:** When `notify_pipe` is readable, this thread re-reads (under mutex protection) `if_vrf_maps` and `vrf_instances` to rebuild its internal `fd_set` for `select()`.
    *   **DHCP Relay Logic:**
        *   **Client to Kea:** When a BOOTREQUEST is received on a client listening socket, it identifies the mapped VRF (using `if_vrf_map_t.vrf_idx`), sets `giaddr` to the client-facing interface's IP, and forwards the packet to the target VRF's Kea instance via its `kea_comm_fd`. Access to `if_vrf_maps` and `vrf_instances` is mutex-protected.
        *   **Kea to Client:** When a BOOTREPLY is received on a `kea_comm_fd`, it finds the corresponding client-facing interface mapping, and uses `sendmsg` with `IP_PKTINFO` to send the reply from the correct source IP of that interface. Access to shared data is mutex-protected.
    *   Periodically checks `global_shutdown_flag` to terminate.
    *   Basic Kea process status checking (`waitpid WNOHANG`) is currently in this thread's timeout block, but could be moved.

*   **Netlink Monitoring Thread (`netlink_thread_func`):**
    *   Dedicated to handling VRF dynamics.
    *   Opens and binds a Netlink socket (`netlink_fd`) to `RTMGRP_LINK`.
    *   Enters a loop (using `select()` or blocking `recvmsg()`) to read Netlink messages.
    *   Parses `RTM_NEWLINK` and `RTM_DELLINK` messages for interfaces of type "vrf".
    *   **VRF Addition:** If a new VRF is detected and not already managed (and within `MAX_VRFS`):
        *   Acquires `vrf_list_mutex`.
        *   Sets up the namespace, veth, Kea instance, and Kea communication socket.
        *   Calls `resolve_vrf_indices_for_maps()` (which acquires `map_list_mutex` and `vrf_list_mutex`).
        *   Releases `vrf_list_mutex`.
        *   Writes to `notify_pipe` to signal the Packet Dispatching Thread.
    *   **VRF Deletion:** If a managed VRF is deleted:
        *   Acquires `vrf_list_mutex`.
        *   Cleans up all resources for that VRF.
        *   Calls `resolve_vrf_indices_for_maps()`.
        *   Releases `vrf_list_mutex`.
        *   Writes to `notify_pipe`.
    *   Periodically checks `global_shutdown_flag` to terminate.

*   **Synchronization:**
    *   `vrf_list_mutex`: Protects `vrf_instances` array and `num_vrfs`.
    *   `map_list_mutex`: Protects `if_vrf_maps` array and `num_if_vrf_maps`.
    *   `notify_pipe`: A self-pipe mechanism used by the Netlink thread and the main thread (for SIGHUP reload) to wake up the Packet Dispatching Thread's `select()` call, prompting it to rebuild its set of monitored file descriptors.

*   **Interface-to-VRF Mappings (`if_vrf_map_t`):** Stores interface name, its IP (string and binary form), target VRF name, the listening socket FD for client packets on this interface, and a resolved index (`vrf_idx`) to the `vrf_instances` array.
*   **VRF Instance Data (`vrf_instance_t`):** Stores VRF name, namespace details, veth details, Kea PID, and the Kea communication socket FD.
*   **Signal Handling:**
    *   `SIGINT`/`SIGTERM`: Handled by `app_signal_handler` which sets `global_shutdown_flag` and writes to `notify_pipe` to ensure threads wake up and terminate.
    *   `SIGHUP`: Handled by `sighup_handler` which sets `reload_config_flag`. The main thread checks this flag to initiate config reload.

*   **Linux Network Namespace, veth Pair, Kea Instance:** Functionality remains as previously described.
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

*   **Threaded Architecture:** The application now uses three main threads (Main, Packet Dispatch, Netlink Monitoring) to separate concerns and improve responsiveness. Pthreads library is used.
*   **Synchronization:** Mutexes (`vrf_list_mutex`, `map_list_mutex`) are used to protect shared data structures accessed by multiple threads. A pipe (`notify_pipe`) is used to signal the packet dispatch thread to update its `select()` file descriptor sets after configuration changes (VRF add/delete or mapping reloads).
*   **Configuration of Mappings (Startup and Runtime):** (Largely as previously described with config file and SIGHUP, but now operates within the threaded model where the main thread handles SIGHUP reload and signals dispatch).
*   **Per-Interface Sockets for Client Traffic:** (Unchanged from previous description).
*   **`giaddr` Setting:** (Unchanged).
*   **Reply Source IP (`IP_PKTINFO`):** (Unchanged).
*   **Dynamic VRF Management (Netlink):** Now handled in a dedicated Netlink thread.
*   **Error Handling:** Basic. Thread creation and mutex/pipe initialization errors are checked. Thread joining is implemented for graceful shutdown.

## 5. Future Enhancements

*   **DHCPv6 Relay Support.**
*   **Full Netlink Integration for network setup/teardown** (replacing `ip` command execution within the C code, potentially in the Netlink thread or helper functions called by it).
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
