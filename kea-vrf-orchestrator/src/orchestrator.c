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
int client_listen_fd = -1; // Global for now: socket to listen for DHCP client broadcasts
int netlink_fd = -1;       // Socket for receiving Netlink RTMGRP_LINK messages

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
    int max_fd = 0; // Will be determined dynamically

    // Setup Netlink socket for link state monitoring (Step 2.1)
    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (netlink_fd < 0) {
        LOG_ERROR("Failed to create Netlink socket");
        // Not necessarily fatal for existing relay logic, but dynamic add/delete won't work
        // We can choose to exit or continue without this feature. For now, log and continue.
    } else {
        struct sockaddr_nl nl_addr;
        memset(&nl_addr, 0, sizeof(nl_addr));
        nl_addr.nl_family = AF_NETLINK;
        nl_addr.nl_groups = RTMGRP_LINK; // Subscribe to link notifications

        if (bind(netlink_fd, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) < 0) {
            LOG_ERROR("Failed to bind Netlink socket");
            close(netlink_fd);
            netlink_fd = -1; // Mark as unusable
        } else {
            LOG_INFO("Netlink socket created (FD: %d) and bound for RTMGRP_LINK.", netlink_fd);
        }
    }


    while(1) {
        FD_ZERO(&read_fds);
        max_fd = 0;

        if (client_listen_fd != -1) {
            FD_SET(client_listen_fd, &read_fds);
            if (client_listen_fd > max_fd) max_fd = client_listen_fd;
        }

        for (int i = 0; i < num_vrfs; ++i) {
            if (vrf_instances[i].kea_comm_fd != -1) {
                FD_SET(vrf_instances[i].kea_comm_fd, &read_fds);
                if (vrf_instances[i].kea_comm_fd > max_fd) {
                    max_fd = vrf_instances[i].kea_comm_fd;
                }
            }
        }

        if (netlink_fd != -1) {
            FD_SET(netlink_fd, &read_fds);
            if (netlink_fd > max_fd) max_fd = netlink_fd;
        }

        if (max_fd == 0 && num_vrfs == 0 && client_listen_fd == -1 && netlink_fd == -1) {
            LOG_INFO("No active file descriptors to monitor. Sleeping before retry or exit.");
            sleep(5); // Avoid busy loop if everything is down
            // Potentially re-initialize or exit if this state persists
            discover_vrfs(); // Try to re-discover if nothing is running.
            // This could lead to re-setup if VRFs appear.
            // If still num_vrfs == 0, then it will sleep again.
            // This basic re-discovery isn't full dynamic handling yet.
            if(num_vrfs == 0 && discovered_vrf_count > 0) { // If discovery found VRFs but setup failed
                 // Attempt to re-initialize VRF instances if discovery found some but setup failed previously
                LOG_INFO("Attempting to re-initialize VRF instances based on fresh discovery.");
                // This logic for re-initialization needs to be robust similar to initial setup in main()
                // For now, this is a simple placeholder for recovery.
                // The main loop in main() which calls setup functions would be more appropriate for re-init.
            }
            continue;
        }


        struct timeval timeout;
        timeout.tv_sec = 10; // Timeout for select, e.g., for periodic checks (like Kea process status)
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

        // If client_listen_fd is set, process incoming client DHCP packet
        if (FD_ISSET(client_listen_fd, &read_fds)) {
            char buffer[DHCP_PACKET_BUFFER_SIZE];
            struct sockaddr_in client_src_addr;
            socklen_t client_src_addr_len = sizeof(client_src_addr);
            ssize_t len = recvfrom(client_listen_fd, buffer, sizeof(buffer), 0,
                                   (struct sockaddr*)&client_src_addr, &client_src_addr_len);

            if (len < (ssize_t)sizeof(dhcp_packet_t) - (ssize_t)sizeof( ((dhcp_packet_t*)0)->options) ) { // Basic check for min DHCP packet size
                 if (len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    LOG_ERROR("recvfrom client_listen_fd failed");
                 } else if (len >=0) {
                    LOG_DEBUG("Received short packet (%zd bytes) on client_listen_fd, ignoring.", len);
                 }
                 // continue or handle error
            } else {
                LOG_INFO("Received %zd bytes from client %s:%d on client_listen_fd",
                         len, inet_ntoa(client_src_addr.sin_addr), ntohs(client_src_addr.sin_port));

                dhcp_packet_t *dhcp_req = (dhcp_packet_t *)buffer;

                if (dhcp_req->op == 1) { // BOOTREQUEST
                    // For Phase 1, relay to the first VRF instance.
                    // TODO: Need a mechanism to map client (e.g. by interface or source IP subnet) to VRF.
                    if (num_vrfs > 0 && vrf_instances[0].kea_comm_fd != -1) {
                        vrf_instance_t *target_vrf = &vrf_instances[0];
                        LOG_DEBUG("Relaying BOOTREQUEST from client to VRF %s (Kea IP: %s)",
                                  target_vrf->name, target_vrf->veth_ns_ip);

                        // Set giaddr
                        // dhcp_req->giaddr = inet_addr(target_vrf->veth_host_ip); // This IP is where Kea should reply
                        // It seems Kea prefers giaddr to be 0 if the relay is on the same segment as client
                        // Or, it should be an IP on the client's network segment.
                        // For now, let's try setting it to the veth_host_ip, as this is the IP Kea can route back to.
                        if (dhcp_req->giaddr == 0) { // Only set if not already set by another relay
                           if (inet_pton(AF_INET, target_vrf->veth_host_ip, &(dhcp_req->giaddr)) != 1) {
                                LOG_ERROR("Failed to convert veth_host_ip %s to network address for giaddr", target_vrf->veth_host_ip);
                                // continue or error
                           }
                        }
                        // dhcp_req->hops++; // Increment hops if acting as a full relay

                        struct sockaddr_in kea_dest_addr;
                        memset(&kea_dest_addr, 0, sizeof(kea_dest_addr));
                        kea_dest_addr.sin_family = AF_INET;
                        kea_dest_addr.sin_port = htons(DHCP_SERVER_PORT);
                        if (inet_pton(AF_INET, target_vrf->veth_ns_ip, &kea_dest_addr.sin_addr) <= 0) {
                            LOG_ERROR("Invalid Kea ns IP address for VRF %s: %s", target_vrf->name, target_vrf->veth_ns_ip);
                            // continue or error
                        }

                        if (sendto(target_vrf->kea_comm_fd, buffer, len, 0,
                                   (struct sockaddr *)&kea_dest_addr, sizeof(kea_dest_addr)) < 0) {
                            LOG_ERROR("sendto failed when relaying to Kea for VRF %s", target_vrf->name);
                        } else {
                            LOG_INFO("Relayed client packet to Kea for VRF %s", target_vrf->name);
                        }
                    } else {
                        LOG_WARN("No VRFs available or Kea socket not ready to relay client request.");
                    }
                } else {
                    LOG_DEBUG("Received non-BOOTREQUEST packet (op=%d) on client_listen_fd, ignoring.", dhcp_req->op);
                }
            }
        }

        // Check Kea communication sockets
        for (int i = 0; i < num_vrfs; ++i) {
            if (vrf_instances[i].kea_comm_fd != -1 && FD_ISSET(vrf_instances[i].kea_comm_fd, &read_fds)) {
                char buffer[DHCP_PACKET_BUFFER_SIZE];
                struct sockaddr_in kea_src_addr; // Kea's actual source IP (should be veth_ns_ip)
                socklen_t kea_src_addr_len = sizeof(kea_src_addr);
                ssize_t len = recvfrom(vrf_instances[i].kea_comm_fd, buffer, sizeof(buffer), 0,
                                       (struct sockaddr*)&kea_src_addr, &kea_src_addr_len);

                if (len < (ssize_t)sizeof(dhcp_packet_t) - (ssize_t)sizeof( ((dhcp_packet_t*)0)->options) ) {
                    if (len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                        LOG_ERROR("recvfrom kea_comm_fd for VRF %s failed", vrf_instances[i].name);
                    } else if (len >=0 ) {
                        LOG_DEBUG("Received short packet (%zd bytes) from Kea for VRF %s, ignoring.", len, vrf_instances[i].name);
                    }
                    // continue or handle error
                } else {
                    LOG_INFO("Received %zd bytes from Kea for VRF %s (source %s:%d)",
                             len, vrf_instances[i].name, inet_ntoa(kea_src_addr.sin_addr), ntohs(kea_src_addr.sin_port));

                    dhcp_packet_t *dhcp_reply = (dhcp_packet_t *)buffer;

                    if (dhcp_reply->op == 2) { // BOOTREPLY
                        if (client_listen_fd != -1) { // Ensure client socket is valid
                            struct sockaddr_in client_dest_addr;
                            memset(&client_dest_addr, 0, sizeof(client_dest_addr));
                            client_dest_addr.sin_family = AF_INET;
                            client_dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
                            client_dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

                            if (sendto(client_listen_fd, buffer, len, 0,
                                       (struct sockaddr *)&client_dest_addr, sizeof(client_dest_addr)) < 0) {
                                LOG_ERROR("sendto failed when relaying to client for VRF %s", vrf_instances[i].name);
                            } else {
                                LOG_INFO("Relayed Kea reply to client broadcast for VRF %s", vrf_instances[i].name);
                            }
                        } else {
                            LOG_WARN("Client listen socket is not valid, cannot relay Kea reply for VRF %s.", vrf_instances[i].name);
                        }
                    } else {
                        LOG_DEBUG("Received non-BOOTREPLY packet (op=%d) from Kea for VRF %s, ignoring.", dhcp_reply->op, vrf_instances[i].name);
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

    if (client_listen_fd != -1) {
        LOG_INFO("Closing client listening socket FD %d.", client_listen_fd);
        close(client_listen_fd);
        client_listen_fd = -1;
    }
    if (netlink_fd != -1) {
        LOG_INFO("Closing Netlink socket FD %d.", netlink_fd);
        close(netlink_fd);
        netlink_fd = -1;
    }
    exit(0);
}


int main(int argc, char *argv[]) {
    LOG_INFO("Kea Per-VRF DHCP Service Orchestrator starting...");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Ensure config directory exists (relative to build/orchestrator)
    // This path might need to be more robust or configurable
    struct stat st = {0};
    if (stat(KEA_CONFIG_DIR, &st) == -1) {
        LOG_INFO("Creating Kea config directory: %s", KEA_CONFIG_DIR);
        if (mkdir(KEA_CONFIG_DIR, 0755) == -1 && errno != EEXIST) {
             LOG_ERROR("Failed to create Kea config directory %s", KEA_CONFIG_DIR);
             return EXIT_FAILURE;
        }
    }


    discover_vrfs(); // Simplified for now

    if (discovered_vrf_count == 0) {
        LOG_INFO("No VRFs discovered. Exiting.");
        return EXIT_SUCCESS;
    }
    if (discovered_vrf_count > MAX_VRFS) {
        LOG_ERROR("Discovered %d VRFs, but MAX_VRFS is %d. Some will be ignored.", discovered_vrf_count, MAX_VRFS);
        discovered_vrf_count = MAX_VRFS;
    }

    num_vrfs = 0; // Reset actual number of successfully processed VRFs
    for (int i = 0; i < discovered_vrf_count; ++i) {
        // Initialize the new instance before attempting cleanup or setup
        memset(&vrf_instances[num_vrfs], 0, sizeof(vrf_instance_t)); // Clears PIDs, IPs, names
        vrf_instances[num_vrfs].kea_comm_fd = -1; // Important initialization for sockets

        strncpy(vrf_instances[num_vrfs].name, discovered_vrf_names[i], MAX_VRF_NAME_LEN - 1);
        vrf_instances[num_vrfs].name[MAX_VRF_NAME_LEN - 1] = '\0'; // Ensure null termination

        LOG_INFO("Processing discovered VRF: %s", vrf_instances[num_vrfs].name);

        // Populate names needed for a targeted pre-cleanup, then call cleanup.
        // This ensures cleanup_vrf_instance has the correct names to find old resources.
        snprintf(vrf_instances[num_vrfs].ns_name, sizeof(vrf_instances[num_vrfs].ns_name), "%s_ns", vrf_instances[num_vrfs].name);
        snprintf(vrf_instances[num_vrfs].veth_host, IFNAMSIZ, "v%.8s_h", vrf_instances[num_vrfs].name);
        // Note: veth_ns, IPs, PIDs are not needed for the pre-cleanup of named network objects.
        // kea_comm_fd is already -1.

        // Attempt cleanup first for this specific VRF name in case of previous unclean shutdown
        cleanup_vrf_instance(&vrf_instances[num_vrfs]); // Cleans based on ns_name and veth_host


        if (setup_namespace_for_vrf(&vrf_instances[num_vrfs], num_vrfs) == 0) {
            if (launch_kea_in_namespace(&vrf_instances[num_vrfs]) == 0) {
                if (setup_kea_communication_socket(&vrf_instances[num_vrfs]) == 0) {
                    num_vrfs++; // Increment *actual* count of successfully set up VRFs
                } else {
                    LOG_ERROR("Failed to setup Kea communication socket for VRF %s. Cleaning up.", vrf_instances[num_vrfs].name);
                    // launch_kea_in_namespace succeeded, so Kea might be running. cleanup_vrf_instance will stop it.
                    cleanup_vrf_instance(&vrf_instances[num_vrfs]);
                }
            } else {
                LOG_ERROR("Failed to launch Kea for VRF %s. Cleaning up this VRF's resources.", vrf_instances[num_vrfs].name);
                cleanup_vrf_instance(&vrf_instances[num_vrfs]);
                // Do not increment num_vrfs for this one
            }
        } else {
            LOG_ERROR("Failed to setup namespace for VRF %s. Resources might be partially created.", vrf_instances[num_vrfs].name);
            // Attempt cleanup for this VRF as setup might have partially succeeded
            cleanup_vrf_instance(&vrf_instances[num_vrfs]);
            // Do not increment num_vrfs
        }
    }

    if (num_vrfs == 0) {
        LOG_ERROR("Failed to set up any VRF instances successfully. Exiting.");
        return EXIT_FAILURE;
    }

    LOG_INFO("Successfully set up %d VRF instance(s).", num_vrfs);

    listen_and_dispatch_packets(); // Main loop

    // Cleanup (normally reached only if listen_and_dispatch_packets exits, or via signal handler)
    for (int i = 0; i < num_vrfs; ++i) {
        cleanup_vrf_instance(&vrf_instances[i]);
    }

    LOG_INFO("Orchestrator shut down.");
    return EXIT_SUCCESS;
}
