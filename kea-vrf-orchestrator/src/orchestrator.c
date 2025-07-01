#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h> // For setns
#include <sys/stat.h> // For mkdir
#include <netinet/udp.h> // For udphdr
#include <netinet/ip.h>  // For ip.h
#include <net/if.h>      // For IFNAMSIZ, ifreq, if_arp.h might be needed for htype
#include <sys/ioctl.h>   // For SIOCGIFADDR, etc.
#include <sys/select.h>  // For select()
#include <linux/rtnetlink.h> // For Netlink RTMGRP_LINK messages
#include <getopt.h>      // For getopt_long()

// Basic logging macros
#define LOG_INFO(msg, ...) fprintf(stdout, "[INFO] " msg "\n", ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) fprintf(stderr, "[ERROR] (%s:%d:%s) " msg "\n", __FILE__, __LINE__, strerror(errno), ##__VA_ARGS__)
#define LOG_DEBUG(msg, ...) fprintf(stdout, "[DEBUG] " msg "\n", ##__VA_ARGS__)

#define MAX_VRFS 10
#define MAX_VRF_NAME_LEN 64
#define KEA_CONFIG_DIR "../config" // Relative to where orchestrator is run from (e.g., build/)
#define SCRIPT_DIR "../scripts"     // Relative to where orchestrator is run from
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_PACKET_BUFFER_SIZE 1024 // Max DHCP packet size can be 576 (RFC2131 Sec 2), options can extend it

// Simplified DHCP Packet Structure (enough for basic relay operations)
// See RFC 2131 for full details. Options field is variable.
// This struct doesn't handle options parsing itself but provides space.
#pragma pack(push, 1) // Ensure structure is packed (no padding)
typedef struct {
    uint8_t op;      // Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY
    uint8_t htype;   // Hardware address type, see ARP section in "Assigned Numbers" RFC; e.g., '1' = 10mb ethernet.
    uint8_t hlen;    // Hardware address length (e.g. '6' for 10mb ethernet).
    uint8_t hops;    // Client sets to zero, optionally used by relay agents when booting via a relay agent.
    uint32_t xid;     // Transaction ID, a random number chosen by the client.
    uint16_t secs;    // Filled in by client, seconds elapsed since client began address acquisition or renewal process.
    uint16_t flags;   // Flags (e.g. broadcast flag at bit 15).
    uint32_t ciaddr;  // Client IP address; only filled in if client is in BOUND, RENEW or REBINDING state.
    uint32_t yiaddr;  // 'your' (client) IP address.
    uint32_t siaddr;  // IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK by server.
    uint32_t giaddr;  // Relay agent IP address, used in booting via a relay agent.
    uint8_t chaddr[16]; // Client hardware address.
    uint8_t sname[64];  // Optional server host name, null terminated string.
    uint8_t file[128];  // Boot file name, null terminated string.
    uint32_t magic_cookie; // Should be 0x63825363
    uint8_t options[DHCP_PACKET_BUFFER_SIZE - 240]; // Placeholder for options (236 for cookie + options)
} dhcp_packet_t;
#pragma pack(pop)


// Structure to hold VRF information
typedef struct {
    char name[MAX_VRF_NAME_LEN];
    char ns_name[MAX_VRF_NAME_LEN + 4]; // <vrf_name>_ns
    char veth_host[IFNAMSIZ];
    char veth_ns[IFNAMSIZ];
    char veth_host_ip[16]; // e.g. 169.254.X.1
    char veth_ns_ip[16];   // e.g. 169.254.X.2
    pid_t kea4_pid;
    pid_t kea6_pid;
    int kea_comm_fd; // Socket for communicating with this VRF's Kea instance (UDP)
} vrf_instance_t;

vrf_instance_t vrf_instances[MAX_VRFS];
int num_vrfs = 0;
// int client_listen_fd = -1; // Will be replaced by per-interface sockets
int netlink_fd = -1;       // Socket for receiving Netlink RTMGRP_LINK messages

#define MAX_IF_VRF_MAPS 10 // Max number of interface-to-VRF mappings

typedef struct {
    char if_name[IFNAMSIZ];
    char vrf_name[MAX_VRF_NAME_LEN];
    char if_ip_str[16]; // Store the IP address string for this interface
    struct in_addr if_ip;   // Binary IP address for giaddr and source IP
    int listen_fd;      // Socket FD for listening on this interface
    int vrf_idx;        // Index into vrf_instances array once resolved
} if_vrf_map_t;

if_vrf_map_t if_vrf_maps[MAX_IF_VRF_MAPS];
int num_if_vrf_maps = 0;

// Placeholder for discovered VRF names from the system
char discovered_vrf_names[MAX_VRFS][MAX_VRF_NAME_LEN];
int discovered_vrf_count = 0;


int run_command(const char *command, char *args[]) {
    pid_t pid = fork();
    if (pid == -1) {
        LOG_ERROR("Failed to fork for command: %s", command);
        return -1;
    } else if (pid == 0) {
        // Child process
        if (execvp(command, args) == -1) {
            LOG_ERROR("Failed to execute command: %s", command);
            exit(EXIT_FAILURE);
        }
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            LOG_DEBUG("Command '%s %s...' executed successfully.", command, args[1] ? args[1] : "");
            return 0;
        } else {
            LOG_ERROR("Command '%s %s...' failed with status %d.", command, args[1] ? args[1] : "", WEXITSTATUS(status));
            return -1;
        }
    }
    return 0; // Should not reach here
}


// Function to discover VRFs
void discover_vrfs() {
    LOG_INFO("Discovering VRFs...");
    discovered_vrf_count = 0;
    FILE *fp;
    char path[1035]; // Buffer for command output line
    char line[256];

    // Execute the command "ip link show type vrf"
    // A more robust solution might use "ip -details link show type vrf" to also get table IDs if needed later.
    fp = popen("ip link show type vrf", "r");
    if (fp == NULL) {
        LOG_ERROR("Failed to run command 'ip link show type vrf'");
        return;
    }

    // Read the output line by line
    // Example output lines:
    // 8: vrf-red@NONE: <NOARP,MASTER,UP,LOWER_UP> mtu 65536 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    //     link/ether 1a:2b:3c:4d:5e:6f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    //     vrf table 101
    while (fgets(path, sizeof(path) - 1, fp) != NULL) {
        // Clean up newline characters
        path[strcspn(path, "\n")] = 0;
        path[strcspn(path, "\r")] = 0;

        // Check if the line contains ": <" which is typical for link definitions, and "vrf"
        // A simple heuristic: find "<dev_name>@NONE" or "<dev_name>:"
        char *name_start = strchr(path, ':');
        if (name_start && name_start[1] == ' ') { // Looks like "X: vrf-name ..."
            name_start += 2; // Skip ": "
            char *name_end = strchr(name_start, '@'); // for "vrf-name@NONE"
            if (!name_end) {
                name_end = strchr(name_start, ':'); // for "vrf-name:" (if no @NONE)
            }

            if (name_end) {
                // Check if this line also indicates it's a VRF by looking for " type vrf " or similar context if needed.
                // However, "ip link show type vrf" should only list VRFs.
                // We need to be careful if the VRF name itself contains '@' or ':'.
                // A more robust parsing might involve sscanf or regex if available.
                // For now, simple extraction.

                int name_len = name_end - name_start;
                if (name_len > 0 && name_len < MAX_VRF_NAME_LEN) {
                    strncpy(discovered_vrf_names[discovered_vrf_count], name_start, name_len);
                    discovered_vrf_names[discovered_vrf_count][name_len] = '\0';
                    LOG_INFO("Found VRF: %s", discovered_vrf_names[discovered_vrf_count]);
                    discovered_vrf_count++;
                    if (discovered_vrf_count >= MAX_VRFS) {
                        LOG_WARN("Reached MAX_VRFS limit (%d), some VRFs may be ignored.", MAX_VRFS);
                        break;
                    }
                }
            }
        }
    }

    if (pclose(fp) == -1) {
        LOG_ERROR("Error closing 'ip link show type vrf' command stream.");
    } else {
        if (discovered_vrf_count > 0) {
            LOG_INFO("Successfully discovered %d VRF(s).", discovered_vrf_count);
        } else {
            LOG_INFO("No VRFs discovered by 'ip link show type vrf'.");
        }
    }
}

// Setup network namespace, veth pairs, and IP addresses for a VRF
int setup_namespace_for_vrf(vrf_instance_t *vrf, int vrf_index) {
    LOG_INFO("Setting up namespace for VRF: %s", vrf->name);

    snprintf(vrf->ns_name, sizeof(vrf->ns_name), "%s_ns", vrf->name);
    // Sanitize vrf->name for use in interface names if it contains invalid characters
    // For simplicity, this is omitted here but important for robustness.
    // E.g. replace '-' with '_' or ensure it's alphanumeric.
    char sanitized_vrf_name[MAX_VRF_NAME_LEN];
    strncpy(sanitized_vrf_name, vrf->name, MAX_VRF_NAME_LEN);
    // Basic sanitization: replace problematic characters if any for interface names.
    // Here, we assume VRF names are already valid or this step is added.
    // For veth names, length is also a concern (max 15 chars for IFNAMSIZ).
    // veth_ + up to 8 chars for VRF name + _h/_ns = 5 + 8 + 3 = 16 (too long)
    // Let's use a shorter prefix or ensure VRF names are short.
    // Using first 8 chars of VRF name for veth. Ensure IFNAMSIZ compatibility.
    // Max length of IFNAMSIZ is typically 16. "v" + 8 (vrf) + "_h" or "_ns" = 1 + 8 + 2 = 11. This is safe.
    snprintf(vrf->veth_host, IFNAMSIZ, "v%.8s_h", vrf->name);
    snprintf(vrf->veth_ns, IFNAMSIZ, "v%.8s_ns", vrf->name);

    snprintf(vrf->veth_host_ip, sizeof(vrf->veth_host_ip), "169.254.%d.1", vrf_index +1);
    snprintf(vrf->veth_ns_ip, sizeof(vrf->veth_ns_ip), "169.254.%d.2", vrf_index +1);

    vrf->kea_comm_fd = -1; // Initialize socket FD, will be created later if setup is successful

    // 1. Create network namespace: ip netns add <ns_name>
    char *cmd_netns_add[] = {"ip", "netns", "add", vrf->ns_name, NULL};
    if (run_command("ip", cmd_netns_add) != 0) {
        LOG_ERROR("Failed to create namespace %s", vrf->ns_name);
        // Could be that it already exists, try to delete and recreate for idempotency in testing
        char *cmd_netns_del_existing[] = {"ip", "netns", "del", vrf->ns_name, NULL};
        run_command("ip", cmd_netns_del_existing); // Best effort delete
        if (run_command("ip", cmd_netns_add) != 0) return -1; // Try again
    }

    // 2. Create veth pair: ip link add <veth_host> type veth peer name <veth_ns>
    char *cmd_veth_add[] = {"ip", "link", "add", vrf->veth_host, "type", "veth", "peer", "name", vrf->veth_ns, NULL};
    if (run_command("ip", cmd_veth_add) != 0) {
        LOG_ERROR("Failed to create veth pair for %s", vrf->name);
        return -1;
    }

    // 3. Move veth_ns to the namespace: ip link set <veth_ns> netns <ns_name>
    char *cmd_veth_set_ns[] = {"ip", "link", "set", vrf->veth_ns, "netns", vrf->ns_name, NULL};
    if (run_command("ip", cmd_veth_set_ns) != 0) {
        LOG_ERROR("Failed to move %s to namespace %s", vrf->veth_ns, vrf->ns_name);
        return -1;
    }

    // 4. Configure IP for host veth: ip addr add <veth_host_ip>/30 dev <veth_host>
    char host_ip_cidr[20];
    snprintf(host_ip_cidr, sizeof(host_ip_cidr), "%s/30", vrf->veth_host_ip);
    char *cmd_veth_host_ip[] = {"ip", "addr", "add", host_ip_cidr, "dev", vrf->veth_host, NULL};
    if (run_command("ip", cmd_veth_host_ip) != 0) {
        LOG_ERROR("Failed to set IP for %s", vrf->veth_host);
        return -1;
    }

    // 5. Bring up host veth: ip link set <veth_host> up
    char *cmd_veth_host_up[] = {"ip", "link", "set", vrf->veth_host, "up", NULL};
    if (run_command("ip", cmd_veth_host_up) != 0) {
        LOG_ERROR("Failed to bring up %s", vrf->veth_host);
        return -1;
    }

    // 6. Configure IP for namespace veth: ip netns exec <ns_name> ip addr add <veth_ns_ip>/30 dev <veth_ns>
    char ns_ip_cidr[20];
    snprintf(ns_ip_cidr, sizeof(ns_ip_cidr), "%s/30", vrf->veth_ns_ip);
    char *cmd_veth_ns_ip[] = {"ip", "netns", "exec", vrf->ns_name, "ip", "addr", "add", ns_ip_cidr, "dev", vrf->veth_ns, NULL};
    if (run_command("ip", cmd_veth_ns_ip) != 0) {
        LOG_ERROR("Failed to set IP for %s in %s", vrf->veth_ns, vrf->ns_name);
        return -1;
    }

    // 7. Bring up namespace veth: ip netns exec <ns_name> ip link set <veth_ns> up
    char *cmd_veth_ns_up[] = {"ip", "netns", "exec", vrf->ns_name, "ip", "link", "set", vrf->veth_ns, "up", NULL};
    if (run_command("ip", cmd_veth_ns_up) != 0) {
        LOG_ERROR("Failed to bring up %s in %s", vrf->veth_ns, vrf->ns_name);
        return -1;
    }

    // 8. Bring up loopback in namespace: ip netns exec <ns_name> ip link set lo up
    char *cmd_lo_up[] = {"ip", "netns", "exec", vrf->ns_name, "ip", "link", "set", "lo", "up", NULL};
     if (run_command("ip", cmd_lo_up) != 0) {
        LOG_ERROR("Failed to bring up lo in %s", vrf->ns_name);
        return -1;
    }

    LOG_INFO("Namespace %s and veth pair %s<>%s configured for VRF %s.", vrf->ns_name, vrf->veth_host, vrf->veth_ns, vrf->name);
    return 0;
}

int setup_kea_communication_socket(vrf_instance_t *vrf) {
    if (vrf->kea_comm_fd != -1) {
        LOG_WARN("Kea communication socket for VRF %s already exists (FD %d). Closing first.", vrf->name, vrf->kea_comm_fd);
        close(vrf->kea_comm_fd);
        vrf->kea_comm_fd = -1;
    }

    vrf->kea_comm_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (vrf->kea_comm_fd < 0) {
        LOG_ERROR("Failed to create Kea communication socket for VRF %s", vrf->name);
        return -1;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(DHCP_SERVER_PORT); // Replies from Kea come to this port if giaddr is set
    if (inet_pton(AF_INET, vrf->veth_host_ip, &bind_addr.sin_addr) <= 0) {
        LOG_ERROR("Invalid host veth IP address for VRF %s: %s", vrf->name, vrf->veth_host_ip);
        close(vrf->kea_comm_fd);
        vrf->kea_comm_fd = -1;
        return -1;
    }

    if (bind(vrf->kea_comm_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG_ERROR("Failed to bind Kea communication socket to %s:%d for VRF %s", vrf->veth_host_ip, DHCP_SERVER_PORT, vrf->name);
        close(vrf->kea_comm_fd);
        vrf->kea_comm_fd = -1;
        return -1;
    }

    // Set non-blocking (optional, but good for select/poll loops)
    // int flags = fcntl(vrf->kea_comm_fd, F_GETFL, 0);
    // if (flags == -1) { LOG_ERROR("fcntl F_GETFL failed for kea_comm_fd"); }
    // if (fcntl(vrf->kea_comm_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    //     LOG_ERROR("fcntl F_SETFL O_NONBLOCK failed for kea_comm_fd");
    // }

    LOG_INFO("Kea communication socket created for VRF %s (FD: %d), bound to %s:%d", vrf->name, vrf->kea_comm_fd, vrf->veth_host_ip, DHCP_SERVER_PORT);
    return 0;
}


// Launch Kea DHCP server(s) in the specified namespace
// For now, only DHCPv4
int launch_kea_in_namespace(vrf_instance_t *vrf) {
    LOG_INFO("Launching Kea for VRF %s in namespace %s", vrf->name, vrf->ns_name);

    char kea_config_file[256];
    snprintf(kea_config_file, sizeof(kea_config_file), "%s/kea-dhcp4-%s.conf", KEA_CONFIG_DIR, vrf->name);

    // Create a dummy Kea config file for this VRF if it doesn't exist
    // In a real scenario, this would be templated and customized.
    FILE *fp = fopen(kea_config_file, "r");
    if (!fp) {
        LOG_INFO("Kea config %s not found, creating dummy.", kea_config_file);
        fp = fopen(kea_config_file, "w");
        if (!fp) {
            LOG_ERROR("Failed to create dummy Kea config %s", kea_config_file);
            return -1;
        }
        fprintf(fp, "{\n");
        fprintf(fp, "    \"Dhcp4\": {\n");
        fprintf(fp, "        \"interfaces-config\": {\n");
        fprintf(fp, "            \"interfaces\": [ \"%s/%s\" ]\n", vrf->veth_ns, vrf->veth_ns_ip); // Listen on specific IP within NS
        fprintf(fp, "        },\n");
        fprintf(fp, "        \"lease-database\": {\n");
        fprintf(fp, "            \"type\": \"memfile\",\n");
        fprintf(fp, "            \"lfc-interval\": 3600\n");
        fprintf(fp, "        },\n");
        fprintf(fp, "        \"subnet4\": [\n");
        fprintf(fp, "            {\n");
        fprintf(fp, "                \"subnet\": \"192.168.%d.0/24\",\n", num_vrfs + 1); // Unique subnet per VRF for PoC
        fprintf(fp, "                \"pools\": [ { \"pool\": \"192.168.%d.10 - 192.168.%d.200\" } ]\n", num_vrfs + 1, num_vrfs + 1);
        fprintf(fp, "            }\n");
        fprintf(fp, "        ]\n");
        fprintf(fp, "    }\n");
        fprintf(fp, "}\n");
        fclose(fp);
        LOG_INFO("Created dummy Kea config %s", kea_config_file);
    } else {
        fclose(fp);
    }


    pid_t pid = fork();
    if (pid == -1) {
        LOG_ERROR("Failed to fork for Kea DHCPv4");
        return -1;
    } else if (pid == 0) {
        // Child process: run kea-dhcp4 in the namespace
        char *kea_args[] = {"kea-dhcp4", "-c", kea_config_file, NULL};

        // Construct the full command for ip netns exec
        char full_command[512];
        snprintf(full_command, sizeof(full_command), "ip netns exec %s kea-dhcp4 -c %s", vrf->ns_name, kea_config_file);

        LOG_DEBUG("Executing: %s", full_command);

        // Need to switch to the namespace before exec
        // This is tricky with fork/exec directly. Using `ip netns exec` is simpler.
        // For direct C control:
        // int fd = open(netns_path, O_RDONLY | O_CLOEXEC);
        // if (fd < 0) { LOG_ERROR("Failed to open netns file %s", netns_path); exit(EXIT_FAILURE); }
        // if (setns(fd, CLONE_NEWNET) < 0) { LOG_ERROR("setns failed for %s", netns_path); close(fd); exit(EXIT_FAILURE); }
        // close(fd);
        // execvp("kea-dhcp4", kea_args);

        // Using ip netns exec approach for simplicity now
        char *cmd_netns_exec[] = {"ip", "netns", "exec", vrf->ns_name, "kea-dhcp4", "-c", kea_config_file, NULL};
        if (execvp("ip", cmd_netns_exec) == -1) {
            LOG_ERROR("Failed to execute kea-dhcp4 in namespace %s", vrf->ns_name);
            exit(EXIT_FAILURE);
        }
        // Should not reach here
        exit(EXIT_SUCCESS);
    } else {
        // Parent process
        vrf->kea4_pid = pid;
        LOG_INFO("Kea DHCPv4 process started for VRF %s with PID %d", vrf->name, pid);
    }
    // TODO: Launch kea-dhcp6 similarly
    return 0;
}

// Main packet listening and dispatching loop
void listen_and_dispatch_packets() {
    LOG_INFO("Starting packet dispatching loop...");
    // This is a placeholder for the complex logic of:
    LOG_INFO("Initializing packet dispatching logic...");

    // 1.3. Socket Setup for Client-Facing Interface (Simplified)
    client_listen_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client_listen_fd < 0) {
        LOG_ERROR("Failed to create client listening socket");
        return; // Critical failure
    }

    int broadcast_enable = 1;
    if (setsockopt(client_listen_fd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        LOG_ERROR("Failed to set SO_BROADCAST on client listening socket");
        close(client_listen_fd);
        client_listen_fd = -1;
        return; // Critical failure
    }
    // For receiving on specific interface, SO_BINDTODEVICE could be used, but requires CAP_NET_RAW.
    // Binding to INADDR_ANY is simpler for now if orchestrator is on same L2 as clients or gateway.

    struct sockaddr_in client_bind_addr;
    memset(&client_bind_addr, 0, sizeof(client_bind_addr));
    client_bind_addr.sin_family = AF_INET;
    client_bind_addr.sin_port = htons(DHCP_SERVER_PORT); // Listen on port 67 for client broadcasts
    client_bind_addr.sin_addr.s_addr = INADDR_ANY;       // Listen on all interfaces

    if (bind(client_listen_fd, (struct sockaddr *)&client_bind_addr, sizeof(client_bind_addr)) < 0) {
        LOG_ERROR("Failed to bind client listening socket to port %d", DHCP_SERVER_PORT);
        close(client_listen_fd);
        client_listen_fd = -1;
        return; // Critical failure
    }
    LOG_INFO("Client listening socket created (FD: %d), bound to INADDR_ANY:%d", client_listen_fd, DHCP_SERVER_PORT);

    // Main select loop
    fd_set read_fds;
    int max_fd = 0;

    // Setup Netlink socket (moved from here to main() to be set up before initial VRF discovery/setup)

    while(1) {
        FD_ZERO(&read_fds);
        max_fd = 0;

        // Add per-interface client listening sockets
        for (int i = 0; i < num_if_vrf_maps; ++i) {
            if (if_vrf_maps[i].listen_fd != -1) {
                FD_SET(if_vrf_maps[i].listen_fd, &read_fds);
                if (if_vrf_maps[i].listen_fd > max_fd) {
                    max_fd = if_vrf_maps[i].listen_fd;
                }
            }
        }

        // Add Kea communication sockets
        for (int i = 0; i < num_vrfs; ++i) {
            if (vrf_instances[i].kea_comm_fd != -1) {
                FD_SET(vrf_instances[i].kea_comm_fd, &read_fds);
                if (vrf_instances[i].kea_comm_fd > max_fd) {
                    max_fd = vrf_instances[i].kea_comm_fd;
                }
            }
        }

        // Add Netlink socket
        if (netlink_fd != -1) {
            FD_SET(netlink_fd, &read_fds);
            if (netlink_fd > max_fd) max_fd = netlink_fd;
        }

        // If there are no FDs to monitor (e.g. no mappings, no VRFs, Netlink failed)
        if (max_fd == 0) {
            LOG_INFO("No active file descriptors to monitor. Sleeping.");
            sleep(5);
            // Potentially try to re-evaluate mappings or VRFs if dynamic changes are expected
            // For now, if all mappings are gone and no VRFs setup, it will just sleep.
            // If Netlink is up, it might detect new VRFs.
            // If mappings are added via a dynamic config mechanism later, that would re-populate FDs.
            continue;
        }

        struct timeval timeout;
        timeout.tv_sec = 10; // Timeout for select, e.g., for periodic checks
        timeout.tv_usec = 0;

        LOG_DEBUG("Calling select() with max_fd %d...", max_fd);
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0 && errno != EINTR) {
            LOG_ERROR("select() error");
            // Potentially break or handle more gracefully
            sleep(1); // Avoid busy loop on persistent error
            continue;
        }

        if (activity == 0) {
            LOG_DEBUG("select() timed out. Heartbeat: Orchestrator running.");
             // Check status of Kea processes (can be moved to a less frequent check)
            for (int i = 0; i < num_vrfs; ++i) {
                if (vrf_instances[i].kea4_pid > 0) {
                    int status;
                    pid_t result = waitpid(vrf_instances[i].kea4_pid, &status, WNOHANG);
                    if (result == vrf_instances[i].kea4_pid) {
                        LOG_ERROR("Kea DHCPv4 for VRF %s (PID %d) has exited.", vrf_instances[i].name, vrf_instances[i].kea4_pid);
                        vrf_instances[i].kea4_pid = 0; // Mark as exited
                        // TODO: Potentially restart it or cleanup its communication socket if it's not auto-restarted
                    } else if (result == -1 && errno != ECHILD && errno != EINTR) {
                         LOG_ERROR("Error waiting for Kea DHCPv4 for VRF %s (PID %d).", vrf_instances[i].name, vrf_instances[i].kea4_pid);
                    }
                }
            }
            continue;
        }

        // Check per-interface client listening sockets
        for (int map_idx = 0; map_idx < num_if_vrf_maps; ++map_idx) {
            if (if_vrf_maps[map_idx].listen_fd != -1 && FD_ISSET(if_vrf_maps[map_idx].listen_fd, &read_fds)) {
                char buffer[DHCP_PACKET_BUFFER_SIZE];
                struct sockaddr_in client_src_addr;
                socklen_t client_src_addr_len = sizeof(client_src_addr);
                ssize_t len = recvfrom(if_vrf_maps[map_idx].listen_fd, buffer, sizeof(buffer), 0,
                                       (struct sockaddr*)&client_src_addr, &client_src_addr_len);

                if (len < (ssize_t)sizeof(dhcp_packet_t) - (ssize_t)sizeof(((dhcp_packet_t*)0)->options)) {
                    if (len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                        LOG_ERROR("recvfrom on client interface %s (FD %d) failed", if_vrf_maps[map_idx].if_name, if_vrf_maps[map_idx].listen_fd);
                    } else if (len >=0) {
                        LOG_DEBUG("Short packet (%zd bytes) on client interface %s, ignoring.", len, if_vrf_maps[map_idx].if_name);
                    }
                } else {
                    LOG_INFO("Received %zd bytes from client %s:%d on interface %s (FD %d)",
                             len, inet_ntoa(client_src_addr.sin_addr), ntohs(client_src_addr.sin_port),
                             if_vrf_maps[map_idx].if_name, if_vrf_maps[map_idx].listen_fd);

                    dhcp_packet_t *dhcp_req = (dhcp_packet_t *)buffer;
                    if (dhcp_req->op == 1) { // BOOTREQUEST
                        int target_vrf_idx = if_vrf_maps[map_idx].vrf_idx;

                        if (target_vrf_idx != -1 && target_vrf_idx < num_vrfs) {
                            vrf_instance_t *target_vrf = &vrf_instances[target_vrf_idx];
                            if (target_vrf->kea_comm_fd != -1) { // Check if Kea's socket is ready
                                LOG_DEBUG("Relaying BOOTREQUEST from client on %s (IP %s) to VRF %s (Kea IP: %s)",
                                          if_vrf_maps[map_idx].if_name,
                                          if_vrf_maps[map_idx].if_ip_str,
                                          target_vrf->name,
                                          target_vrf->veth_ns_ip);

                                // Set giaddr to the IP of the interface that received the client's broadcast
                                if (dhcp_req->giaddr == 0) { // Only set if not already set by another relay
                                    dhcp_req->giaddr = if_vrf_maps[map_idx].if_ip.s_addr;
                                }
                                // dhcp_req->hops++; // Optional: if acting as a standards-compliant relay

                                struct sockaddr_in kea_dest_addr;
                            memset(&kea_dest_addr, 0, sizeof(kea_dest_addr));
                            kea_dest_addr.sin_family = AF_INET;
                            kea_dest_addr.sin_port = htons(DHCP_SERVER_PORT);
                            if (inet_pton(AF_INET, target_vrf->veth_ns_ip, &kea_dest_addr.sin_addr) <= 0) {
                                LOG_ERROR("Invalid Kea ns IP for VRF %s: %s", target_vrf->name, target_vrf->veth_ns_ip);
                                continue; // Skip to next readable FD in select()
                            }

                            if (sendto(target_vrf->kea_comm_fd, buffer, len, 0,
                                       (struct sockaddr *)&kea_dest_addr, sizeof(kea_dest_addr)) < 0) {
                                LOG_ERROR("sendto failed relaying to Kea for VRF %s from interface %s", target_vrf->name, if_vrf_maps[map_idx].if_name);
                            } else {
                                LOG_INFO("Relayed client packet from %s to Kea for VRF %s", if_vrf_maps[map_idx].if_name, target_vrf->name);
                            }
                        } else {
                            LOG_WARN("Target VRF %s for interface %s has no active Kea communication socket.",
                                     (target_vrf_idx != -1 && target_vrf_idx < num_vrfs) ? vrf_instances[target_vrf_idx].name : "N/A",
                                     if_vrf_maps[map_idx].if_name);
                        }
                    } else {
                        LOG_WARN("No valid target VRF resolved for request from interface %s (mapped to VRF name '%s', resolved index %d). Packet dropped.",
                                 if_vrf_maps[map_idx].if_name, if_vrf_maps[map_idx].vrf_name, target_vrf_idx);
                    }
                } else {
                    LOG_DEBUG("Non-BOOTREQUEST (op=%d) on interface %s, ignoring.", dhcp_req->op, if_vrf_maps[map_idx].if_name);
                    }
                }
            }
        }

        // Check Kea communication sockets (for replies from Kea)
        for (int i = 0; i < num_vrfs; ++i) { // Iterate through all potentially active VRF instances
            if (vrf_instances[i].kea_comm_fd != -1 && FD_ISSET(vrf_instances[i].kea_comm_fd, &read_fds)) {
                char buffer[DHCP_PACKET_BUFFER_SIZE];
                struct sockaddr_in kea_src_addr;
                socklen_t kea_src_addr_len = sizeof(kea_src_addr);
                ssize_t len = recvfrom(vrf_instances[i].kea_comm_fd, buffer, sizeof(buffer), 0,
                                       (struct sockaddr*)&kea_src_addr, &kea_src_addr_len);

                if (len < (ssize_t)sizeof(dhcp_packet_t) - (ssize_t)sizeof(((dhcp_packet_t*)0)->options)) {
                     if (len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                        LOG_ERROR("recvfrom kea_comm_fd for VRF %s failed", vrf_instances[i].name);
                    } else if (len >=0 ) {
                        LOG_DEBUG("Short packet (%zd bytes) from Kea for VRF %s, ignoring.", len, vrf_instances[i].name);
                    }
                } else {
                    LOG_INFO("Received %zd bytes from Kea for VRF %s (source %s:%d)",
                             len, vrf_instances[i].name, inet_ntoa(kea_src_addr.sin_addr), ntohs(kea_src_addr.sin_port));

                    dhcp_packet_t *dhcp_reply = (dhcp_packet_t *)buffer;
                    if (dhcp_reply->op == 2) { // BOOTREPLY
                        // Determine which client-facing interface this reply corresponds to.
                        // This requires that the original request's if_vrf_map index was stored or can be found.
                        // For now, we find the if_vrf_map entry that points to this vrf_instance.
                        // This assumes a one-to-one mapping from a client iface to a VRF for relay for simplicity.
                        // If a VRF can be reached by multiple client ifaces, this needs more thought.
                        int reply_map_idx = -1;
                        for(int k=0; k < num_if_vrf_maps; ++k) {
                            if (if_vrf_maps[k].vrf_idx == i) { // 'i' is the index of vrf_instances
                                reply_map_idx = k;
                                break;
                            }
                        }

                        if (reply_map_idx != -1 && if_vrf_maps[reply_map_idx].listen_fd != -1) {
                            // Use sendmsg with IP_PKTINFO to set source IP for the reply.
                            // For now, simple sendto broadcast via the specific interface's listening socket.
                            // This might not set source IP correctly if socket is INADDR_ANY.
                            // Step 4: Use sendmsg with IP_PKTINFO to set source IP for the reply.
                            struct sockaddr_in client_dest_addr;
                            memset(&client_dest_addr, 0, sizeof(client_dest_addr));
                            client_dest_addr.sin_family = AF_INET;
                            client_dest_addr.sin_port = htons(DHCP_CLIENT_PORT);

                            // Determine destination IP: yiaddr if available and unicast allowed, else broadcast
                            if (dhcp_reply->yiaddr != 0 && !(ntohs(dhcp_reply->flags) & 0x8000)) { // 0x8000 is BROADCAST flag
                                client_dest_addr.sin_addr.s_addr = dhcp_reply->yiaddr;
                                LOG_DEBUG("Targeting reply to yiaddr: %s", inet_ntoa(client_dest_addr.sin_addr));
                            } else {
                                client_dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
                                LOG_DEBUG("Targeting reply to INADDR_BROADCAST");
                            }

                            struct msghdr msg;
                            struct iovec iov[1];
                            iov[0].iov_base = buffer;
                            iov[0].iov_len = len;

                            // Ancillary data for IP_PKTINFO
                            char cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];

                            memset(&msg, 0, sizeof(msg));
                            msg.msg_name = &client_dest_addr;
                            msg.msg_namelen = sizeof(client_dest_addr);
                            msg.msg_iov = iov;
                            msg.msg_iovlen = 1;
                            msg.msg_control = cmsg_buf;
                            msg.msg_controllen = sizeof(cmsg_buf);

                            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                            cmsg->cmsg_level = IPPROTO_IP;
                            cmsg->cmsg_type = IP_PKTINFO;
                            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

                            struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
                            memset(pktinfo, 0, sizeof(struct in_pktinfo));
                            pktinfo->ipi_spec_dst.s_addr = if_vrf_maps[reply_map_idx].if_ip.s_addr; // Source IP for reply
                            // pktinfo->ipi_ifindex = 0; // Kernel will choose interface based on routing if 0, or set specific if_index if known

                            if (sendmsg(if_vrf_maps[reply_map_idx].listen_fd, &msg, 0) < 0) {
                                LOG_ERROR("sendmsg failed relaying to client via interface %s for VRF %s",
                                          if_vrf_maps[reply_map_idx].if_name, vrf_instances[i].name);
                            } else {
                                LOG_INFO("Relayed Kea reply via sendmsg on interface %s (src IP %s) for VRF %s",
                                         if_vrf_maps[reply_map_idx].if_name,
                                         if_vrf_maps[reply_map_idx].if_ip_str,
                                         vrf_instances[i].name);
                            }
                        } else {
                             LOG_WARN("Could not find client interface mapping to relay Kea reply for VRF %s or listen_fd is invalid.", vrf_instances[i].name);
                        }
                    } else {
                         LOG_DEBUG("Non-BOOTREPLY (op=%d) from Kea for VRF %s, ignoring.", dhcp_reply->op, vrf_instances[i].name);
                    }
                }
            }
        }


        // Handle Netlink messages (Step 2.2)
        if (netlink_fd != -1 && FD_ISSET(netlink_fd, &read_fds)) {
            char nl_buffer[4096];
            struct iovec iov = { nl_buffer, sizeof(nl_buffer) };
            struct sockaddr_nl sa;
            struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
            ssize_t nl_len = recvmsg(netlink_fd, &msg, 0);

            if (nl_len < 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    // Continue
                } else {
                    LOG_ERROR("Netlink recvmsg error");
                    // Potentially close and reopen netlink_fd or stop monitoring
                    close(netlink_fd);
                    netlink_fd = -1;
                }
            } else {
                for (struct nlmsghdr *nh = (struct nlmsghdr *)nl_buffer; NLMSG_OK(nh, nl_len); nh = NLMSG_NEXT(nh, nl_len)) {
                    if (nh->nlmsg_type == NLMSG_DONE) break;
                    if (nh->nlmsg_type == NLMSG_ERROR) {
                         struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(nh);
                         LOG_ERROR("Netlink message error: %s (%d)", strerror(-err->error), -err->error);
                         continue;
                    }
                    if (nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) {
                        struct ifinfomsg *iface_info = (struct ifinfomsg *)NLMSG_DATA(nh);
                        struct rtattr *rta = IFLA_RTA(iface_info);
                        int rta_len = IFLA_PAYLOAD(nh);
                        char if_name[IFNAMSIZ] = {0};
                        char if_kind[IFNAMSIZ] = {0}; // To store IFLA_INFO_KIND

                        for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                            if (rta->rta_type == IFLA_IFNAME) {
                                strncpy(if_name, (char *)RTA_DATA(rta), IFNAMSIZ -1);
                            }
                            if (rta->rta_type == IFLA_LINKINFO) {
                                struct rtattr *linkinfo_rta = (struct rtattr *)RTA_DATA(rta);
                                int linkinfo_rta_len = RTA_PAYLOAD(rta);
                                for(; RTA_OK(linkinfo_rta, linkinfo_rta_len); linkinfo_rta = RTA_NEXT(linkinfo_rta, linkinfo_rta_len)) {
                                    if (linkinfo_rta->rta_type == IFLA_INFO_KIND) {
                                        strncpy(if_kind, (char *)RTA_DATA(linkinfo_rta), IFNAMSIZ -1);
                                        break;
                                    }
                                }
                            }
                        }

                        if (strlen(if_name) > 0 && strcmp(if_kind, "vrf") == 0) {
                            if (nh->nlmsg_type == RTM_NEWLINK) {
                                LOG_INFO("Netlink RTM_NEWLINK: VRF Interface %s appeared.", if_name);
                                int already_managed = 0;
                                for (int k = 0; k < num_vrfs; ++k) {
                                    if (strcmp(vrf_instances[k].name, if_name) == 0) {
                                        already_managed = 1;
                                        LOG_INFO("VRF %s is already managed.", if_name);
                                        break;
                                    }
                                }
                                if (!already_managed) {
                                    if (num_vrfs < MAX_VRFS) {
                                        LOG_INFO("Attempting to dynamically add and manage new VRF: %s", if_name);
                                        vrf_instance_t *new_vrf = &vrf_instances[num_vrfs]; // Tentatively use next slot

                                        memset(new_vrf, 0, sizeof(vrf_instance_t));
                                        new_vrf->kea_comm_fd = -1;
                                        strncpy(new_vrf->name, if_name, MAX_VRF_NAME_LEN -1);
                                        new_vrf->name[MAX_VRF_NAME_LEN -1] = '\0';

                                        // Populate names for potential pre-cleanup (though less likely for dynamic add)
                                        snprintf(new_vrf->ns_name, sizeof(new_vrf->ns_name), "%s_ns", new_vrf->name);
                                        snprintf(new_vrf->veth_host, IFNAMSIZ, "v%.8s_h", new_vrf->name);
                                        // cleanup_vrf_instance(new_vrf); // Optional pre-clean

                                        if (setup_namespace_for_vrf(new_vrf, num_vrfs) == 0) { // Use current num_vrfs for unique indexing
                                            if (launch_kea_in_namespace(new_vrf) == 0) {
                                                if (setup_kea_communication_socket(new_vrf) == 0) {
                                                    LOG_INFO("Successfully added and configured VRF: %s", new_vrf->name);
                                                    num_vrfs++; // Only increment if all steps succeeded
                                                } else {
                                                    LOG_ERROR("Failed to setup Kea communication socket for dynamically added VRF %s.", new_vrf->name);
                                                    cleanup_vrf_instance(new_vrf);
                                                }
                                            } else {
                                                LOG_ERROR("Failed to launch Kea for dynamically added VRF %s.", new_vrf->name);
                                                cleanup_vrf_instance(new_vrf);
                                            }
                                        } else {
                                            LOG_ERROR("Failed to setup namespace for dynamically added VRF %s.", new_vrf->name);
                                            cleanup_vrf_instance(new_vrf); // Cleanup whatever might have been created
                                        }
                                    } else {
                                        LOG_WARN("MAX_VRFS limit reached, cannot add new VRF %s.", if_name);
                                    }
                                }
                            } else if (nh->nlmsg_type == RTM_DELLINK) {
                                LOG_INFO("Netlink RTM_DELLINK: VRF Interface %s disappeared.", if_name);
                                int found_idx = -1;
                                for (int k = 0; k < num_vrfs; ++k) {
                                    if (strcmp(vrf_instances[k].name, if_name) == 0) {
                                        found_idx = k;
                                        break;
                                    }
                                }
                                if (found_idx != -1) {
                                    LOG_INFO("Cleaning up and removing dynamically deleted VRF: %s", vrf_instances[found_idx].name);
                                    cleanup_vrf_instance(&vrf_instances[found_idx]);
                                    // Shift remaining elements left
                                    for (int k = found_idx; k < num_vrfs - 1; ++k) {
                                        vrf_instances[k] = vrf_instances[k+1];
                                    }
                                    num_vrfs--;
                                    LOG_INFO("VRF %s removed. Current number of managed VRFs: %d", if_name, num_vrfs);
                                } else {
                                    LOG_INFO("VRF %s was not actively managed or already removed.", if_name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

void cleanup_vrf_instance(vrf_instance_t *vrf) {
    LOG_INFO("Cleaning up VRF instance: %s", vrf->name);

    // Close communication socket
    if (vrf->kea_comm_fd != -1) {
        LOG_DEBUG("Closing Kea communication socket FD %d for VRF %s", vrf->kea_comm_fd, vrf->name);
        close(vrf->kea_comm_fd);
        vrf->kea_comm_fd = -1;
    }

    // Kill Kea processes
    if (vrf->kea4_pid > 0) {
        LOG_INFO("Stopping Kea DHCPv4 (PID %d) for VRF %s", vrf->kea4_pid, vrf->name);
        kill(vrf->kea4_pid, SIGTERM);
        int status;
        pid_t result = waitpid(vrf->kea4_pid, &status, 0); // Wait for it to terminate
        if (result == -1) {
            LOG_ERROR("Error waiting for Kea DHCPv4 PID %d to terminate.", vrf->kea4_pid);
        }
        vrf->kea4_pid = 0;
    }
    if (vrf->kea6_pid > 0) {
        // kill(vrf->kea6_pid, SIGTERM);
        // waitpid(vrf->kea6_pid, NULL, 0);
        // vrf->kea6_pid = 0;
    }

    // Delete veth pair (deleting one end deletes the pair)
    // Ensure veth_host is not empty before trying to delete
    if (strlen(vrf->veth_host) > 0) {
        char *cmd_veth_del[] = {"ip", "link", "del", vrf->veth_host, NULL};
        if (run_command("ip", cmd_veth_del) != 0) {
            LOG_ERROR("Failed to delete veth %s. It might have been deleted already or namespace cleanup handled it.", vrf->veth_host);
        }
    }


    // Delete network namespace
    // Ensure ns_name is not empty
    if (strlen(vrf->ns_name) > 0) {
        char *cmd_netns_del[] = {"ip", "netns", "del", vrf->ns_name, NULL};
        if (run_command("ip", cmd_netns_del) != 0) {
            LOG_ERROR("Failed to delete namespace %s. It might be in use or already deleted.", vrf->ns_name);
        }
    }

    LOG_INFO("Cleanup for VRF %s completed.", vrf->name);
}

void signal_handler(int sig) {
    LOG_INFO("Caught signal %d. Cleaning up...", sig);
    for (int i = 0; i < num_vrfs; ++i) {
        cleanup_vrf_instance(&vrf_instances[i]);
    }
    // Also remove generated Kea config files
    for (int i = 0; i < num_vrfs; ++i) {
        if (strlen(vrf_instances[i].name) > 0) { // Ensure instance was somewhat valid
            char kea_config_file[256];
            snprintf(kea_config_file, sizeof(kea_config_file), "%s/kea-dhcp4-%s.conf", KEA_CONFIG_DIR, vrf_instances[i].name);
            if (remove(kea_config_file) == 0) {
                LOG_INFO("Removed Kea config file: %s", kea_config_file);
            } else {
                LOG_DEBUG("Could not remove Kea config file: %s (errno %d)", kea_config_file, errno);
            }
        }
    }

    // Close per-interface client listening sockets
    for (int i = 0; i < num_if_vrf_maps; ++i) {
        if (if_vrf_maps[i].listen_fd != -1) {
            LOG_INFO("Closing client listening socket for interface %s (FD %d).", if_vrf_maps[i].if_name, if_vrf_maps[i].listen_fd);
            close(if_vrf_maps[i].listen_fd);
            if_vrf_maps[i].listen_fd = -1;
        }
    }

    if (netlink_fd != -1) {
        LOG_INFO("Closing Netlink socket FD %d.", netlink_fd);
        close(netlink_fd);
        netlink_fd = -1;
    }
    exit(0);
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [-m <if_name>:<vrf_name>:<if_ip>] ...\n", prog_name);
    fprintf(stderr, "  -m <if_name>:<vrf_name>:<if_ip> : Map client interface to a VRF and specify interface IP for giaddr.\n");
    fprintf(stderr, "                                     Example: -m eth1:vrf-red:192.168.1.1\n");
    fprintf(stderr, "  At least one -m mapping is required for relay functionality.\n");
}

int main(int argc, char *argv[]) {
    LOG_INFO("Kea Per-VRF DHCP Service Orchestrator starting...");

    int opt;
    while ((opt = getopt(argc, argv, "m:")) != -1) {
        switch (opt) {
            case 'm':
                if (num_if_vrf_maps >= MAX_IF_VRF_MAPS) {
                    LOG_ERROR("Maximum number of interface-VRF mappings (%d) reached. Ignoring further -m options.", MAX_IF_VRF_MAPS);
                    continue;
                }
                char *if_details = optarg;
                char *token;
                char *saveptr;

                // if_name
                token = strtok_r(if_details, ":", &saveptr);
                if (!token) {
                    LOG_ERROR("Invalid -m format: %s. Expected <if_name>:<vrf_name>:<if_ip>", optarg);
                    continue;
                }
                strncpy(if_vrf_maps[num_if_vrf_maps].if_name, token, IFNAMSIZ -1);
                if_vrf_maps[num_if_vrf_maps].if_name[IFNAMSIZ-1] = '\0';

                // vrf_name
                token = strtok_r(NULL, ":", &saveptr);
                if (!token) {
                    LOG_ERROR("Invalid -m format: %s. Expected <if_name>:<vrf_name>:<if_ip>", optarg);
                    continue;
                }
                strncpy(if_vrf_maps[num_if_vrf_maps].vrf_name, token, MAX_VRF_NAME_LEN -1);
                if_vrf_maps[num_if_vrf_maps].vrf_name[MAX_VRF_NAME_LEN-1] = '\0';

                // if_ip
                token = strtok_r(NULL, ":", &saveptr);
                if (!token) {
                    LOG_ERROR("Invalid -m format: %s. Expected <if_name>:<vrf_name>:<if_ip>", optarg);
                    continue;
                }
                strncpy(if_vrf_maps[num_if_vrf_maps].if_ip_str, token, sizeof(if_vrf_maps[num_if_vrf_maps].if_ip_str) -1);
                if_vrf_maps[num_if_vrf_maps].if_ip_str[sizeof(if_vrf_maps[num_if_vrf_maps].if_ip_str)-1] = '\0';

                if (inet_pton(AF_INET, if_vrf_maps[num_if_vrf_maps].if_ip_str, &if_vrf_maps[num_if_vrf_maps].if_ip) != 1) {
                    LOG_ERROR("Invalid IP address '%s' in mapping for interface %s.",
                              if_vrf_maps[num_if_vrf_maps].if_ip_str, if_vrf_maps[num_if_vrf_maps].if_name);
                    // Reset this map entry by not incrementing num_if_vrf_maps or explicitly clearing.
                    continue;
                }

                if_vrf_maps[num_if_vrf_maps].listen_fd = -1; // To be created later
                if_vrf_maps[num_if_vrf_maps].vrf_idx = -1;   // To be resolved later

                LOG_INFO("Added mapping: Interface '%s' -> VRF '%s' (Interface IP for giaddr: %s)",
                         if_vrf_maps[num_if_vrf_maps].if_name,
                         if_vrf_maps[num_if_vrf_maps].vrf_name,
                         if_vrf_maps[num_if_vrf_maps].if_ip_str);
                num_if_vrf_maps++;
                break;
            default: /* '?' */
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (num_if_vrf_maps == 0) {
        LOG_WARN("No client interface to VRF mappings provided via -m option. DHCP relay functionality will be limited.");
        // Depending on desired behavior, could exit if relay is primary function.
        // For now, it can still manage VRFs dynamically even if it can't relay.
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct stat st = {0};
    if (stat(KEA_CONFIG_DIR, &st) == -1) {
        LOG_INFO("Creating Kea config directory: %s", KEA_CONFIG_DIR);
        if (mkdir(KEA_CONFIG_DIR, 0755) == -1 && errno != EEXIST) {
             LOG_ERROR("Failed to create Kea config directory %s", KEA_CONFIG_DIR);
             return EXIT_FAILURE;
        }
    }

    // Setup Netlink socket for dynamic VRF monitoring (before initial VRF setup)
    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (netlink_fd < 0) {
        LOG_ERROR("Failed to create Netlink socket for VRF monitoring. Dynamic add/delete will not work.");
    } else {
        struct sockaddr_nl nl_addr;
        memset(&nl_addr, 0, sizeof(nl_addr));
        nl_addr.nl_family = AF_NETLINK;
        nl_addr.nl_groups = RTMGRP_LINK;
        if (bind(netlink_fd, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) < 0) {
            LOG_ERROR("Failed to bind Netlink socket. Dynamic add/delete will not work.");
            close(netlink_fd);
            netlink_fd = -1;
        } else {
            LOG_INFO("Netlink socket for VRF monitoring created (FD: %d).", netlink_fd);
        }
    }

    // Initial discovery and setup of pre-existing VRFs
    discover_vrfs();
    // Note: discovered_vrf_count is set by discover_vrfs()
    // num_vrfs is the count of successfully *managed* VRFs.

    // This loop will be modified or augmented by Netlink dynamic handling later
    // For now, it sets up initially discovered VRFs.
    num_vrfs = 0;
    for (int i = 0; i < discovered_vrf_count; ++i) {
        // Initialize the new instance before attempting cleanup or setup
        memset(&vrf_instances[num_vrfs], 0, sizeof(vrf_instance_t)); // Clears PIDs, IPs, names
        vrf_instances[num_vrfs].kea_comm_fd = -1; // Important initialization for sockets

    for (int i = 0; i < discovered_vrf_count; ++i) {
        if (num_vrfs >= MAX_VRFS) {
            LOG_WARN("MAX_VRFS limit reached during initial setup. Ignoring further discovered VRFs.");
            break;
        }
        vrf_instance_t *current_vrf = &vrf_instances[num_vrfs]; // Use pointer for clarity

        memset(current_vrf, 0, sizeof(vrf_instance_t));
        current_vrf->kea_comm_fd = -1;

        strncpy(current_vrf->name, discovered_vrf_names[i], MAX_VRF_NAME_LEN - 1);
        current_vrf->name[MAX_VRF_NAME_LEN - 1] = '\0';

        LOG_INFO("Processing initially discovered VRF: %s", current_vrf->name);

        snprintf(current_vrf->ns_name, sizeof(current_vrf->ns_name), "%s_ns", current_vrf->name);
        snprintf(current_vrf->veth_host, IFNAMSIZ, "v%.8s_h", current_vrf->name);

        cleanup_vrf_instance(current_vrf);

        if (setup_namespace_for_vrf(current_vrf, num_vrfs) == 0) {
            if (launch_kea_in_namespace(current_vrf) == 0) {
                if (setup_kea_communication_socket(current_vrf) == 0) {
                    LOG_INFO("Successfully set up initially discovered VRF: %s", current_vrf->name);
                    num_vrfs++;
                } else {
                    LOG_ERROR("Failed to setup Kea communication socket for initial VRF %s.", current_vrf->name);
                    cleanup_vrf_instance(current_vrf);
                }
            } else {
                LOG_ERROR("Failed to launch Kea for initial VRF %s.", current_vrf->name);
                cleanup_vrf_instance(current_vrf);
            }
        } else {
            LOG_ERROR("Failed to setup namespace for initial VRF %s.", current_vrf->name);
            cleanup_vrf_instance(current_vrf);
        }
    }

    if (num_if_vrf_maps > 0 && num_vrfs == 0) {
         LOG_WARN("Interface mappings provided, but no VRFs were successfully set up initially. Relay will not function until VRFs are active.");
    }
    // It's okay if num_vrfs is 0 initially if we expect them to be added dynamically.

    // Resolve VRF indexes for mappings initially
    for (int i = 0; i < num_if_vrf_maps; ++i) {
        if_vrf_maps[i].vrf_idx = -1; // Ensure it's reset before trying to resolve
        for (int j = 0; j < num_vrfs; ++j) {
            if (strcmp(if_vrf_maps[i].vrf_name, vrf_instances[j].name) == 0) {
                if_vrf_maps[i].vrf_idx = j;
                LOG_INFO("Resolved mapping: Interface '%s' (IP %s) linked to active VRF '%s' (index %d).",
                         if_vrf_maps[i].if_name, if_vrf_maps[i].if_ip_str, vrf_instances[j].name, j);
                break;
            }
        }
        if (if_vrf_maps[i].vrf_idx == -1) {
            LOG_WARN("VRF '%s' for interface map '%s' not (yet) active or discovered during initial setup.",
                     if_vrf_maps[i].vrf_name, if_vrf_maps[i].if_name);
        }
    }

    // Setup listening sockets for each mapped client interface
    for (int i = 0; i < num_if_vrf_maps; ++i) {
        if_vrf_maps[i].listen_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (if_vrf_maps[i].listen_fd < 0) {
            LOG_ERROR("Failed to create client listening socket for interface %s (%s)", if_vrf_maps[i].if_name, if_vrf_maps[i].if_ip_str);
            // This mapping will be unusable. Consider how to handle this - skip or abort? For now, skip.
            continue;
        }

        int broadcast_enable = 1;
        if (setsockopt(if_vrf_maps[i].listen_fd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
            LOG_ERROR("Failed to set SO_BROADCAST on client listening socket for %s", if_vrf_maps[i].if_name);
            close(if_vrf_maps[i].listen_fd);
            if_vrf_maps[i].listen_fd = -1;
            continue;
        }

        // Bind to specific interface IP
        struct sockaddr_in client_bind_addr;
        memset(&client_bind_addr, 0, sizeof(client_bind_addr));
        client_bind_addr.sin_family = AF_INET;
        client_bind_addr.sin_port = htons(DHCP_SERVER_PORT);
        client_bind_addr.sin_addr.s_addr = if_vrf_maps[i].if_ip.s_addr; // Bind to the specific interface IP

        if (bind(if_vrf_maps[i].listen_fd, (struct sockaddr *)&client_bind_addr, sizeof(client_bind_addr)) < 0) {
            LOG_ERROR("Failed to bind client listening socket to %s:%d for interface %s", if_vrf_maps[i].if_ip_str, DHCP_SERVER_PORT, if_vrf_maps[i].if_name);
            close(if_vrf_maps[i].listen_fd);
            if_vrf_maps[i].listen_fd = -1;
            continue;
        }
        LOG_INFO("Client listening socket for interface %s created (FD: %d), bound to %s:%d",
                 if_vrf_maps[i].if_name, if_vrf_maps[i].listen_fd, if_vrf_maps[i].if_ip_str, DHCP_SERVER_PORT);
    }


    listen_and_dispatch_packets();

    // Cleanup (normally reached only via signal handler, but good practice)
    for (int i = 0; i < num_vrfs; ++i) {
        cleanup_vrf_instance(&vrf_instances[i]);
    }

    LOG_INFO("Orchestrator shut down.");
    return EXIT_SUCCESS;
}
