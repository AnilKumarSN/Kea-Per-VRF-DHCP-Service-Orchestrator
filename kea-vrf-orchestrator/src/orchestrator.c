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
#include <ctype.h>       // For isspace()
#include <signal.h>      // For SIGHUP, sig_atomic_t, signal()
#include <pthread.h>     // For threading

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
int netlink_fd = -1;       // Socket for receiving Netlink RTMGRP_LINK messages

#define MAX_IF_VRF_MAPS 10 // Max number of interface-to-VRF mappings

volatile sig_atomic_t reload_config_flag = 0; // Flag for SIGHUP, set by sighup_handler
volatile sig_atomic_t global_shutdown_flag = 0; // Flag for graceful shutdown

pthread_mutex_t vrf_list_mutex;
pthread_mutex_t map_list_mutex;
int notify_pipe[2] = {-1, -1}; // Pipe for waking up dispatch thread [0]=read, [1]=write


typedef struct {
    char if_name[IFNAMSIZ];
    char vrf_name[MAX_VRF_NAME_LEN];
    char if_ip_str[16]; // Store the IP address string for this interface
    struct in_addr if_ip;   // Binary IP address for giaddr and source IP
    int listen_fd;      // Socket FD for listening on this interface
    int vrf_idx;        // Index into vrf_instances array once resolved
    // Keep a copy of the original parsed string for comparison during reload
    char original_map_str[IFNAMSIZ + MAX_VRF_NAME_LEN + 16 + 3];
} if_vrf_map_t;

if_vrf_map_t if_vrf_maps[MAX_IF_VRF_MAPS];
int num_if_vrf_maps = 0;
char *config_file_path = NULL; // Path to the interface mapping config file
int use_config_file_mappings = 0; // Flag to indicate if config file should be used over -m options


// Placeholder for discovered VRF names from the system
char discovered_vrf_names[MAX_VRFS][MAX_VRF_NAME_LEN];
int discovered_vrf_count = 0;

// Forward declaration
int setup_if_map_socket(if_vrf_map_t *map_entry);
void resolve_vrf_indices_for_maps();
int reload_interface_mappings();
void* dispatch_thread_func(void *arg); // Renamed from listen_and_dispatch_packets
void* netlink_thread_func(void *arg);  // New thread function


int run_command(const char *command, char *args[]) {
    pid_t pid = fork();
    if (pid == -1) {
        LOG_ERROR("Failed to fork for command: %s", command);
        return -1;
    } else if (pid == 0) {
        if (execvp(command, args) == -1) {
            LOG_ERROR("Failed to execute command: %s", command);
            exit(EXIT_FAILURE);
        }
    } else {
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
    return 0;
}

void discover_vrfs() {
    LOG_INFO("Discovering VRFs...");
    discovered_vrf_count = 0;
    FILE *fp = popen("ip link show type vrf", "r");
    if (!fp) { LOG_ERROR("Failed to run 'ip link show type vrf'"); return; }
    char path[1035];
    while (fgets(path, sizeof(path) - 1, fp) != NULL) {
        path[strcspn(path, "\n\r")] = 0;
        char *name_start = strchr(path, ':');
        if (name_start && name_start[1] == ' ') {
            name_start += 2;
            char *name_end = strchr(name_start, '@');
            if (!name_end) name_end = strchr(name_start, ':');
            if (name_end) {
                int name_len = name_end - name_start;
                if (name_len > 0 && name_len < MAX_VRF_NAME_LEN) {
                    strncpy(discovered_vrf_names[discovered_vrf_count], name_start, name_len);
                    discovered_vrf_names[discovered_vrf_count][name_len] = '\0';
                    LOG_DEBUG("Found VRF by discovery: %s", discovered_vrf_names[discovered_vrf_count]);
                    discovered_vrf_count++;
                    if (discovered_vrf_count >= MAX_VRFS) {
                        LOG_WARN("MAX_VRFS limit reached during discovery.");
                        break;
                    }
                }
            }
        }
    }
    if (pclose(fp) == -1) LOG_ERROR("Error closing 'ip link show type vrf' stream.");
    else LOG_INFO("VRF discovery complete. Found %d VRF(s).", discovered_vrf_count);
}

int setup_namespace_for_vrf(vrf_instance_t *vrf, int vrf_idx_for_ip) {
    LOG_INFO("Setting up namespace for VRF: %s", vrf->name);
    snprintf(vrf->ns_name, sizeof(vrf->ns_name), "%s_ns", vrf->name);
    snprintf(vrf->veth_host, IFNAMSIZ, "v%.8s_h", vrf->name);
    snprintf(vrf->veth_ns, IFNAMSIZ, "v%.8s_ns", vrf->name);
    snprintf(vrf->veth_host_ip, sizeof(vrf->veth_host_ip), "169.254.%d.1", vrf_idx_for_ip + 1);
    snprintf(vrf->veth_ns_ip, sizeof(vrf->veth_ns_ip), "169.254.%d.2", vrf_idx_for_ip + 1);
    vrf->kea_comm_fd = -1;
    vrf->kea4_pid = 0; // Initialize PIDs
    vrf->kea6_pid = 0;


    char *cmd_netns_add[] = {"ip", "netns", "add", vrf->ns_name, NULL};
    if (run_command("ip", cmd_netns_add) != 0) {
        LOG_DEBUG("NS %s might exist. Trying del/add.", vrf->ns_name);
        char *cmd_del[] = {"ip", "netns", "del", vrf->ns_name, NULL}; run_command("ip", cmd_del);
        if (run_command("ip", cmd_netns_add) != 0) { LOG_ERROR("Failed to create NS %s.", vrf->ns_name); return -1; }
    }
    char *cmds[][10] = {
        {"ip", "link", "add", vrf->veth_host, "type", "veth", "peer", "name", vrf->veth_ns, NULL},
        {"ip", "link", "set", vrf->veth_ns, "netns", vrf->ns_name, NULL},
        {"ip", "addr", "add", NULL, "dev", vrf->veth_host, NULL}, // Placeholder for IP
        {"ip", "link", "set", vrf->veth_host, "up", NULL},
        {"ip", "netns", "exec", vrf->ns_name, "ip", "addr", "add", NULL, "dev", vrf->veth_ns, NULL}, // Placeholder
        {"ip", "netns", "exec", vrf->ns_name, "ip", "link", "set", vrf->veth_ns, "up", NULL},
        {"ip", "netns", "exec", vrf->ns_name, "ip", "link", "set", "lo", "up", NULL}
    };
    char host_ip_cidr[20], ns_ip_cidr[20];
    snprintf(host_ip_cidr, sizeof(host_ip_cidr), "%s/30", vrf->veth_host_ip);
    cmds[2][3] = host_ip_cidr;
    snprintf(ns_ip_cidr, sizeof(ns_ip_cidr), "%s/30", vrf->veth_ns_ip);
    cmds[4][7] = ns_ip_cidr;

    for (size_t i = 0; i < sizeof(cmds)/sizeof(cmds[0]); ++i) {
        if (run_command(cmds[i][0], cmds[i]) != 0) {
            LOG_ERROR("Setup cmd failed for VRF %s: %s %s...", vrf->name, cmds[i][0], cmds[i][1]);
            return -1;
        }
    }
    LOG_INFO("NS %s and veth %s<>%s configured for VRF %s.", vrf->ns_name, vrf->veth_host, vrf->veth_ns, vrf->name);
    return 0;
}

int setup_kea_communication_socket(vrf_instance_t *vrf) {
    if (vrf->kea_comm_fd != -1) { close(vrf->kea_comm_fd); vrf->kea_comm_fd = -1; }
    vrf->kea_comm_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (vrf->kea_comm_fd < 0) { LOG_ERROR("Failed to create Kea comm socket for VRF %s", vrf->name); return -1; }
    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(DHCP_SERVER_PORT);
    if (inet_pton(AF_INET, vrf->veth_host_ip, &bind_addr.sin_addr) <= 0) {
        LOG_ERROR("Invalid veth_host_ip for VRF %s: %s", vrf->name, vrf->veth_host_ip);
        close(vrf->kea_comm_fd); vrf->kea_comm_fd = -1; return -1;
    }
    if (bind(vrf->kea_comm_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG_ERROR("Failed to bind Kea comm socket to %s:%d for VRF %s", vrf->veth_host_ip, DHCP_SERVER_PORT, vrf->name);
        close(vrf->kea_comm_fd); vrf->kea_comm_fd = -1; return -1;
    }
    LOG_INFO("Kea comm socket for VRF %s (FD:%d) bound to %s:%d", vrf->name, vrf->kea_comm_fd, vrf->veth_host_ip, DHCP_SERVER_PORT);
    return 0;
}

int launch_kea_in_namespace(vrf_instance_t *vrf, int current_vrf_count_for_subnet_logic) {
    LOG_INFO("Launching Kea for VRF %s in NS %s (subnet index %d)", vrf->name, vrf->ns_name, current_vrf_count_for_subnet_logic);
    char kea_conf_file[256];
    snprintf(kea_conf_file, sizeof(kea_conf_file), "%s/kea-dhcp4-%s.conf", KEA_CONFIG_DIR, vrf->name);
    FILE *fout = fopen(kea_conf_file, "w");
    if (!fout) { LOG_ERROR("Failed to open Kea config %s for writing", kea_conf_file); return -1; }

    char template_path[256];
    snprintf(template_path, sizeof(template_path), "%s/kea-dhcp4-template.conf", KEA_CONFIG_DIR);
    FILE *ftemplate = fopen(template_path, "r");
    if (ftemplate) {
        LOG_DEBUG("Using template %s for Kea config %s", template_path, kea_conf_file);
        char line[1024], rbuf[1024];
        while(fgets(line, sizeof(line), ftemplate)) {
            char *p;
            #define REPLACE_P(L, PH, RV, RB) p=strstr(L,PH); if(p){strncpy(RB,L,p-L);RB[p-L]='\0';strcat(RB,RV);strcat(RB,p+strlen(PH));strcpy(L,RB);}
            REPLACE_P(line, "%%VETH_NS_INTERFACE%%", vrf->veth_ns, rbuf);
            REPLACE_P(line, "%%VETH_NS_IP%%", vrf->veth_ns_ip, rbuf);
            REPLACE_P(line, "%%VRF_NAME%%", vrf->name, rbuf);
            char sbuf[32], psbuf[32], pebuf[32], gwbuf[32];
            snprintf(sbuf, sizeof(sbuf), "192.168.%d.0/24", (current_vrf_count_for_subnet_logic % 250) + 1);
            snprintf(psbuf, sizeof(psbuf), "192.168.%d.10", (current_vrf_count_for_subnet_logic % 250) + 1);
            snprintf(pebuf, sizeof(pebuf), "192.168.%d.200", (current_vrf_count_for_subnet_logic % 250) + 1);
            snprintf(gwbuf, sizeof(gwbuf), "192.168.%d.1", (current_vrf_count_for_subnet_logic % 250) + 1);
            REPLACE_P(line, "%%SUBNET4_PREFIX%%", sbuf, rbuf);
            REPLACE_P(line, "%%SUBNET4_POOL_START%%", psbuf, rbuf);
            REPLACE_P(line, "%%SUBNET4_POOL_END%%", pebuf, rbuf);
            REPLACE_P(line, "%%SUBNET4_GATEWAY%%", gwbuf, rbuf);
            REPLACE_P(line, "%%DNS_SERVERS%%", "8.8.8.8, 8.8.4.4", rbuf);
            fputs(line, fout);
        }
        fclose(ftemplate);
    } else {
        LOG_WARN("Kea template %s not found. Creating minimal config.", template_path);
        fprintf(fout, "{\"Dhcp4\":{\"interfaces-config\":{\"interfaces\":[\"%s/%s\"]},\"lease-database\":{\"type\":\"memfile\",\"name\":\"/var/lib/kea/kea-leases4-%s.csv\"},\"subnet4\":[{\"subnet\":\"192.168.%d.0/24\",\"pools\":[{\"pool\":\"192.168.%d.10-192.168.%d.200\"}]}]}}", vrf->veth_ns, vrf->veth_ns_ip, vrf->name, (current_vrf_count_for_subnet_logic % 250) + 1, (current_vrf_count_for_subnet_logic % 250) + 1, (current_vrf_count_for_subnet_logic % 250) + 1);
    }
    fclose(fout);
    LOG_INFO("Generated Kea config: %s", kea_conf_file);

    pid_t pid = fork();
    if (pid == -1) { LOG_ERROR("Fork failed for Kea"); return -1; }
    if (pid == 0) {
        char *cmd[] = {"ip", "netns", "exec", vrf->ns_name, "kea-dhcp4", "-c", kea_conf_file, NULL};
        execvp("ip", cmd);
        LOG_ERROR("Exec kea-dhcp4 failed for VRF %s", vrf->name);
        exit(EXIT_FAILURE);
    }
    vrf->kea4_pid = pid;
    LOG_INFO("Kea DHCPv4 for VRF %s started (PID %d)", vrf->name, pid);
    return 0;
}

// Renamed from listen_and_dispatch_packets
void* dispatch_thread_func(void *arg) {
    (void)arg; // Not using argument for now
    LOG_INFO("Packet dispatching thread started.");
    fd_set read_fds;
    int max_fd;

    // This loop should also check global_shutdown_flag
    while(!global_shutdown_flag) {
        if (reload_config_flag) {
            LOG_INFO("Dispatch Thread: Reload config flag detected.");
            pthread_mutex_lock(&map_list_mutex);
            reload_interface_mappings();
            pthread_mutex_unlock(&map_list_mutex);
            reload_config_flag = 0;
        }

        FD_ZERO(&read_fds);
        max_fd = 0;

        pthread_mutex_lock(&map_list_mutex);
        for (int i = 0; i < num_if_vrf_maps; ++i) {
            if (if_vrf_maps[i].listen_fd != -1) {
                FD_SET(if_vrf_maps[i].listen_fd, &read_fds);
                if (if_vrf_maps[i].listen_fd > max_fd) max_fd = if_vrf_maps[i].listen_fd;
            }
        }
        pthread_mutex_unlock(&map_list_mutex);

        pthread_mutex_lock(&vrf_list_mutex);
        for (int i = 0; i < num_vrfs; ++i) {
            if (vrf_instances[i].kea_comm_fd != -1) {
                FD_SET(vrf_instances[i].kea_comm_fd, &read_fds);
                if (vrf_instances[i].kea_comm_fd > max_fd) max_fd = vrf_instances[i].kea_comm_fd;
            }
        }
        pthread_mutex_unlock(&vrf_list_mutex);

        // Add notify_pipe[0] to select set
        if (notify_pipe[0] != -1) {
            FD_SET(notify_pipe[0], &read_fds);
            if (notify_pipe[0] > max_fd) max_fd = notify_pipe[0];
        }
        // We don't add netlink_fd here anymore, it's in its own thread.

        if (max_fd == 0 && notify_pipe[0] == -1) { // If no sockets and no pipe to wake us
            LOG_DEBUG("Dispatch Thread: No FDs to monitor. Sleeping briefly.");
            usleep(100000); // Sleep 100ms to avoid busy loop if pipe also closed
            continue;
        }
        if (max_fd == 0 && notify_pipe[0] != -1) { // Only pipe is active
             max_fd = notify_pipe[0]; // ensure max_fd is at least the pipe
        }


        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0}; // Shorter timeout for responsiveness
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0 && errno != EINTR) { LOG_ERROR("Dispatch Thread: select() error"); usleep(100000); continue; }

        if (global_shutdown_flag) break; // Check flag after select

        if (activity == 0) { // Timeout
            LOG_DEBUG("Dispatch Thread: select() timed out.");
            // Kea process status check can be moved to main thread or a dedicated monitor thread later
            // For now, keeping it here but under lock.
            pthread_mutex_lock(&vrf_list_mutex);
            for (int i = 0; i < num_vrfs; ++i) {
                if (vrf_instances[i].kea4_pid > 0) {
                    int status;
                    pid_t result = waitpid(vrf_instances[i].kea4_pid, &status, WNOHANG);
                    if (result == vrf_instances[i].kea4_pid) {
                        LOG_ERROR("Kea for VRF %s (PID %d) exited.", vrf_instances[i].name, vrf_instances[i].kea4_pid);
                        vrf_instances[i].kea4_pid = 0;
                    } else if (result == -1 && errno != ECHILD) {
                         LOG_ERROR("waitpid error for Kea VRF %s (PID %d)", vrf_instances[i].name, vrf_instances[i].kea4_pid);
                    }
                }
            }
            pthread_mutex_unlock(&vrf_list_mutex);
            continue;
        }

        // Check notify_pipe first
        if (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], &read_fds)) {
            LOG_DEBUG("Dispatch Thread: Notified via pipe. Rebuilding fd_set.");
            char dummy_buf[1];
            ssize_t n = read(notify_pipe[0], dummy_buf, sizeof(dummy_buf)); // Consume the byte
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_ERROR("Error reading from notify_pipe[0]");
            }
            // The fd_set will be rebuilt at the start of the loop.
        }

        pthread_mutex_lock(&map_list_mutex); // Lock before accessing if_vrf_maps
        for (int map_idx = 0; map_idx < num_if_vrf_maps; ++map_idx) {
            if (if_vrf_maps[map_idx].listen_fd != -1 && FD_ISSET(if_vrf_maps[map_idx].listen_fd, &read_fds)) {
                char buffer[DHCP_PACKET_BUFFER_SIZE];
                struct sockaddr_in client_src_addr;
                socklen_t client_src_addr_len = sizeof(client_src_addr);
                ssize_t len = recvfrom(if_vrf_maps[map_idx].listen_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_src_addr, &client_src_addr_len);

                if (len < (ssize_t)(sizeof(dhcp_packet_t) - sizeof(((dhcp_packet_t*)0)->options))) {
                    if(len >= 0) LOG_DEBUG("Short packet (%zd bytes) on if %s.", len, if_vrf_maps[map_idx].if_name);
                    else if (errno != EAGAIN && errno != EWOULDBLOCK) LOG_ERROR("recvfrom on if %s failed", if_vrf_maps[map_idx].if_name);
                } else {
                    LOG_INFO("Rx %zd bytes from client %s:%d on if %s", len, inet_ntoa(client_src_addr.sin_addr), ntohs(client_src_addr.sin_port), if_vrf_maps[map_idx].if_name);
                    dhcp_packet_t *dhcp_req = (dhcp_packet_t *)buffer;
                    if (dhcp_req->op == 1) {
                        int target_vrf_idx = if_vrf_maps[map_idx].vrf_idx;

                        pthread_mutex_lock(&vrf_list_mutex); // Lock vrf_instances
                        if (target_vrf_idx != -1 && target_vrf_idx < num_vrfs) {
                            vrf_instance_t *target_vrf = &vrf_instances[target_vrf_idx];
                            if (target_vrf->kea_comm_fd != -1) {
                                if (dhcp_req->giaddr == 0) dhcp_req->giaddr = if_vrf_maps[map_idx].if_ip.s_addr;
                                struct sockaddr_in kea_dest_addr = {0};
                                kea_dest_addr.sin_family = AF_INET;
                                kea_dest_addr.sin_port = htons(DHCP_SERVER_PORT);
                                if (inet_pton(AF_INET, target_vrf->veth_ns_ip, &kea_dest_addr.sin_addr) <= 0) {
                                    LOG_ERROR("Invalid Kea ns IP for VRF %s: %s", target_vrf->name, target_vrf->veth_ns_ip);
                                    pthread_mutex_unlock(&vrf_list_mutex); continue;
                                }
                                if (sendto(target_vrf->kea_comm_fd, buffer, len, 0, (struct sockaddr *)&kea_dest_addr, sizeof(kea_dest_addr)) < 0) {
                                    LOG_ERROR("sendto to Kea VRF %s from if %s failed", target_vrf->name, if_vrf_maps[map_idx].if_name);
                                } else {
                                    LOG_INFO("Relayed client packet from %s to Kea for VRF %s", if_vrf_maps[map_idx].if_name, target_vrf->name);
                                }
                            } else LOG_WARN("Target VRF %s for if %s has no Kea socket.", target_vrf->name, if_vrf_maps[map_idx].if_name);
                        } else LOG_WARN("No valid VRF for request from if %s (map VRF %s, idx %d). Dropped.", if_vrf_maps[map_idx].if_name, if_vrf_maps[map_idx].vrf_name, target_vrf_idx);
                        pthread_mutex_unlock(&vrf_list_mutex);
                    } else LOG_DEBUG("Non-BOOTREQUEST (op=%d) on if %s. Ignored.", dhcp_req->op, if_vrf_maps[map_idx].if_name);
                }
            }
        }
        pthread_mutex_unlock(&map_list_mutex); // Unlock after iterating if_vrf_maps

        pthread_mutex_lock(&vrf_list_mutex); // Lock before accessing vrf_instances
        for (int i = 0; i < num_vrfs; ++i) {
            if (vrf_instances[i].kea_comm_fd != -1 && FD_ISSET(vrf_instances[i].kea_comm_fd, &read_fds)) {
                char buffer[DHCP_PACKET_BUFFER_SIZE];
                struct sockaddr_in kea_src_addr;
                socklen_t kea_src_addr_len = sizeof(kea_src_addr);
                ssize_t len = recvfrom(vrf_instances[i].kea_comm_fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&kea_src_addr, &kea_src_addr_len);

                if (len < (ssize_t)(sizeof(dhcp_packet_t) - sizeof(((dhcp_packet_t*)0)->options))) {
                    if(len >=0) LOG_DEBUG("Short packet (%zd bytes) from Kea for VRF %s.", len, vrf_instances[i].name);
                    else if(errno != EAGAIN && errno != EWOULDBLOCK) LOG_ERROR("recvfrom Kea for VRF %s failed", vrf_instances[i].name);
                } else {
                    LOG_INFO("Rx %zd bytes from Kea for VRF %s (src %s:%d)", len, vrf_instances[i].name, inet_ntoa(kea_src_addr.sin_addr), ntohs(kea_src_addr.sin_port));
                    dhcp_packet_t *dhcp_reply = (dhcp_packet_t *)buffer;
                    if (dhcp_reply->op == 2) {
                        int reply_map_idx = -1;
                        pthread_mutex_lock(&map_list_mutex); // Lock maps for reading
                        for(int k=0; k < num_if_vrf_maps; ++k) {
                            if (if_vrf_maps[k].vrf_idx == i) { reply_map_idx = k; break; }
                        }

                        if (reply_map_idx != -1 && if_vrf_maps[reply_map_idx].listen_fd != -1) {
                            struct sockaddr_in client_dest_addr = {0};
                            client_dest_addr.sin_family = AF_INET;
                            client_dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
                            if (dhcp_reply->yiaddr != 0 && !(ntohs(dhcp_reply->flags) & 0x8000)) {
                                client_dest_addr.sin_addr.s_addr = dhcp_reply->yiaddr;
                            } else {
                                client_dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
                            }

                            struct msghdr msg = {0};
                            struct iovec iov = {buffer, len};
                            char cmsg_buf[CMSG_SPACE(sizeof(struct in_pktinfo))];
                            msg.msg_name = &client_dest_addr; msg.msg_namelen = sizeof(client_dest_addr);
                            msg.msg_iov = &iov; msg.msg_iovlen = 1;
                            msg.msg_control = cmsg_buf; msg.msg_controllen = sizeof(cmsg_buf);
                            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                            cmsg->cmsg_level = IPPROTO_IP; cmsg->cmsg_type = IP_PKTINFO;
                            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
                            struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
                            memset(pktinfo, 0, sizeof(struct in_pktinfo));
                            pktinfo->ipi_spec_dst.s_addr = if_vrf_maps[reply_map_idx].if_ip.s_addr;

                            if (sendmsg(if_vrf_maps[reply_map_idx].listen_fd, &msg, 0) < 0) {
                                LOG_ERROR("sendmsg failed for Kea reply via if %s for VRF %s", if_vrf_maps[reply_map_idx].if_name, vrf_instances[i].name);
                            } else {
                                LOG_INFO("Relayed Kea reply via sendmsg on if %s (src IP %s) for VRF %s", if_vrf_maps[reply_map_idx].if_name, if_vrf_maps[reply_map_idx].if_ip_str, vrf_instances[i].name);
                            }
                        } else LOG_WARN("No client if map for Kea reply from VRF %s.", vrf_instances[i].name);
                        pthread_mutex_unlock(&map_list_mutex);
                    } else LOG_DEBUG("Non-BOOTREPLY (op=%d) from Kea for VRF %s.", dhcp_reply->op, vrf_instances[i].name);
                }
            }
        }
        pthread_mutex_unlock(&vrf_list_mutex); // Unlock vrf_instances access

        if (netlink_fd != -1 && FD_ISSET(netlink_fd, &read_fds)) {
            // This part will be moved to netlink_thread_func
            // For now, it stays, but needs mutex protection for shared data access
            LOG_DEBUG("Dispatch Thread: Netlink activity detected (will be handled by Netlink thread).");
            // char nl_dummy_buf[1];
            // read(netlink_fd, nl_dummy_buf, sizeof(nl_dummy_buf)); // consume to clear from select, actual processing in netlink thread
        }
    }
    LOG_INFO("Packet dispatching thread finished.");
    return NULL;
}

void* netlink_thread_func(void *arg) {
    (void)arg;
    LOG_INFO("Netlink monitoring thread started.");
    // Setup Netlink socket (if not already done in main and passed or global)
    // For now, assume netlink_fd is global and setup in main.
    // If it failed in main, this thread might not do much.

    if (netlink_fd == -1) {
        LOG_ERROR("Netlink thread: Netlink FD is invalid. Thread exiting.");
        return NULL;
    }

    while(!global_shutdown_flag) {
        char nl_buffer[4096];
        struct iovec iov = { nl_buffer, sizeof(nl_buffer) };
        struct sockaddr_nl sa;
        struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

        // Use select for timeout and shutdown check, or make recvmsg non-blocking
        fd_set nl_read_fds;
        FD_ZERO(&nl_read_fds);
        FD_SET(netlink_fd, &nl_read_fds);
        struct timeval nl_timeout = {.tv_sec = 1, .tv_usec = 0}; // Check shutdown flag periodically

        int activity = select(netlink_fd + 1, &nl_read_fds, NULL, NULL, &nl_timeout);

        if (activity < 0 && errno != EINTR) {
            LOG_ERROR("Netlink Thread: select() error");
            // Consider closing and reopening netlink_fd on certain errors
            sleep(1); // Avoid busy loop
            continue;
        }
        if (global_shutdown_flag) break;
        if (activity == 0) continue; // Timeout, loop to check shutdown_flag

        if (FD_ISSET(netlink_fd, &nl_read_fds)) {
            ssize_t nl_len = recvmsg(netlink_fd, &msg, 0); // MSG_DONTWAIT for non-blocking
            if (nl_len < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOG_ERROR("Netlink Thread: recvmsg error");
                    // Potentially close and re-init netlink_fd or stop monitoring
                    close(netlink_fd); netlink_fd = -1; pthread_exit(NULL); // Exit thread on unrecoverable error
                }
                continue;
            }

            for (struct nlmsghdr *nh = (struct nlmsghdr *)nl_buffer; NLMSG_OK(nh, nl_len); nh = NLMSG_NEXT(nh, nl_len)) {
                if (nh->nlmsg_type == NLMSG_DONE) break;
                if (nh->nlmsg_type == NLMSG_ERROR) {
                     struct nlmsgerr *err_msg = (struct nlmsgerr*)NLMSG_DATA(nh);
                     LOG_ERROR("Netlink Thread: Netlink message error: %s (%d)", strerror(-err_msg->error), -err_msg->error); continue;
                }
                if (nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) {
                    struct ifinfomsg *iface_info = (struct ifinfomsg *)NLMSG_DATA(nh);
                    struct rtattr *rta = IFLA_RTA(iface_info);
                    int rta_len = IFLA_PAYLOAD(nh);
                    char if_name[IFNAMSIZ] = {0}, if_kind[IFNAMSIZ] = {0};
                    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                        if (rta->rta_type == IFLA_IFNAME) strncpy(if_name, (char *)RTA_DATA(rta), IFNAMSIZ -1);
                        if (rta->rta_type == IFLA_LINKINFO) {
                            struct rtattr *l_rta = (struct rtattr *)RTA_DATA(rta);
                            int l_rta_len = RTA_PAYLOAD(rta);
                            for(; RTA_OK(l_rta, l_rta_len); l_rta = RTA_NEXT(l_rta, l_rta_len)) {
                                if (l_rta->rta_type == IFLA_INFO_KIND) {
                                    strncpy(if_kind, (char *)RTA_DATA(l_rta), IFNAMSIZ -1); break;
                                }
                            }
                        }
                    }
                    if (strlen(if_name) > 0 && strcmp(if_kind, "vrf") == 0) {
                        pthread_mutex_lock(&vrf_list_mutex);
                        pthread_mutex_lock(&map_list_mutex); // Need map_list_mutex for resolve_vrf_indices_for_maps

                        if (nh->nlmsg_type == RTM_NEWLINK) {
                            LOG_INFO("Netlink Thread: RTM_NEWLINK for VRF %s.", if_name);
                            int already_managed = 0;
                            for (int k = 0; k < num_vrfs; ++k) {
                                if (strcmp(vrf_instances[k].name, if_name) == 0) {
                                    already_managed = 1; LOG_INFO("VRF %s already managed.", if_name); break;
                                }
                            }
                            if (!already_managed && num_vrfs < MAX_VRFS) {
                                vrf_instance_t *new_vrf = &vrf_instances[num_vrfs];
                                memset(new_vrf, 0, sizeof(vrf_instance_t));
                                new_vrf->kea_comm_fd = -1;
                                strncpy(new_vrf->name, if_name, MAX_VRF_NAME_LEN -1);
                                if (setup_namespace_for_vrf(new_vrf, num_vrfs) == 0 &&
                                    launch_kea_in_namespace(new_vrf, num_vrfs) == 0 &&
                                    setup_kea_communication_socket(new_vrf) == 0) {
                                    LOG_INFO("Netlink Thread: Dynamically added VRF: %s", new_vrf->name);
                                    num_vrfs++;
                                    resolve_vrf_indices_for_maps();
                                    if (pipe(notify_pipe) != -1) write(notify_pipe[1], "U", 1); // Signal dispatch thread
                                } else {
                                    LOG_ERROR("Netlink Thread: Failed to setup new VRF %s.", new_vrf->name);
                                    cleanup_vrf_instance(new_vrf);
                                }
                            } else if (num_vrfs >= MAX_VRFS) LOG_WARN("Netlink Thread: MAX_VRFS limit. Cannot add VRF %s.", if_name);
                        } else if (nh->nlmsg_type == RTM_DELLINK) {
                            LOG_INFO("Netlink Thread: RTM_DELLINK for VRF %s.", if_name);
                            int found_idx = -1;
                            for (int k = 0; k < num_vrfs; ++k) {
                                if (strcmp(vrf_instances[k].name, if_name) == 0) { found_idx = k; break; }
                            }
                            if (found_idx != -1) {
                                LOG_INFO("Netlink Thread: Cleaning up deleted VRF: %s (idx %d)", vrf_instances[found_idx].name, found_idx);
                                cleanup_vrf_instance(&vrf_instances[found_idx]);
                                for (int k = found_idx; k < num_vrfs - 1; ++k) vrf_instances[k] = vrf_instances[k+1];
                                num_vrfs--;
                                LOG_INFO("Netlink Thread: VRF %s removed. Managed VRFs: %d", if_name, num_vrfs);
                                resolve_vrf_indices_for_maps();
                                if (pipe(notify_pipe) != -1) write(notify_pipe[1], "U", 1); // Signal dispatch thread
                            } else LOG_INFO("Netlink Thread: Deleted VRF %s was not managed.", if_name);
                        }
                        pthread_mutex_unlock(&map_list_mutex);
                        pthread_mutex_unlock(&vrf_list_mutex);
                    }
                }
            }
        }
    }
    LOG_INFO("Netlink monitoring thread finished.");
    return NULL;
}


void cleanup_vrf_instance(vrf_instance_t *vrf) {
    LOG_INFO("Cleaning up VRF instance: %s", vrf->name);

    if (vrf->kea_comm_fd != -1) {
        LOG_DEBUG("Closing Kea communication socket FD %d for VRF %s", vrf->kea_comm_fd, vrf->name);
        close(vrf->kea_comm_fd);
        vrf->kea_comm_fd = -1;
    }

    if (vrf->kea4_pid > 0) {
        LOG_INFO("Stopping Kea DHCPv4 (PID %d) for VRF %s", vrf->kea4_pid, vrf->name);
        kill(vrf->kea4_pid, SIGTERM);
        int status;
        pid_t result = waitpid(vrf->kea4_pid, &status, 0);
        if (result == -1) {
            LOG_ERROR("Error waiting for Kea DHCPv4 PID %d to terminate.", vrf->kea4_pid);
        }
        vrf->kea4_pid = 0;
    }

    if (strlen(vrf->veth_host) > 0) {
        char *cmd_veth_del[] = {"ip", "link", "del", vrf->veth_host, NULL};
        if (run_command("ip", cmd_veth_del) != 0) {
            LOG_ERROR("Failed to delete veth %s. It might have been deleted already or namespace cleanup handled it.", vrf->veth_host);
        }
    }

    if (strlen(vrf->ns_name) > 0) {
        char *cmd_netns_del[] = {"ip", "netns", "del", vrf->ns_name, NULL};
        if (run_command("ip", cmd_netns_del) != 0) {
            LOG_ERROR("Failed to delete namespace %s. It might be in use or already deleted.", vrf->ns_name);
        }
    }

    LOG_INFO("Cleanup for VRF %s completed.", vrf->name);
}

// Centralized function to resolve VRF names in if_vrf_maps to vrf_instances indices
void resolve_vrf_indices_for_maps() {
    LOG_DEBUG("Resolving VRF indices for all interface mappings...");
    for (int i = 0; i < num_if_vrf_maps; ++i) {
        if_vrf_maps[i].vrf_idx = -1; // Reset before trying to resolve
        for (int j = 0; j < num_vrfs; ++j) {
            if (strcmp(if_vrf_maps[i].vrf_name, vrf_instances[j].name) == 0) {
                if_vrf_maps[i].vrf_idx = j;
                LOG_INFO("Resolved mapping: Iface '%s' (IP %s) to VRF '%s' (idx %d)",
                         if_vrf_maps[i].if_name, if_vrf_maps[i].if_ip_str,
                         vrf_instances[j].name, j);
                break;
            }
        }
        if (if_vrf_maps[i].vrf_idx == -1) {
            LOG_WARN("VRF '%s' for if_map '%s' is not currently active/managed.",
                     if_vrf_maps[i].vrf_name, if_vrf_maps[i].if_name);
        }
    }
}


void sighup_handler(int sig) {
    (void)sig; // Unused parameter to prevent compiler warnings
    // This is a signal handler, keep it short and simple.
    // Just set a flag that the main loop will check.
    LOG_INFO("SIGHUP received, flagging for configuration reload.");
    reload_config_flag = 1;
    // Re-registering the handler is good practice on some older systems,
    // though on modern Linux, disposition is usually not reset.
    // For SA_RESETHAND behavior, it would be needed. Default is usually persistent.
    // signal(SIGHUP, sighup_handler); // Not strictly necessary on modern Linux but harmless.
}

void app_signal_handler(int sig) {
    LOG_INFO("Caught signal %d. Initiating shutdown...", sig);
    global_shutdown_flag = 1;
    // Write to notify_pipe to wake up select in dispatch_thread_func if it's blocking
    if (notify_pipe[1] != -1) {
        char dummy = 'S'; // S for Shutdown
        if (write(notify_pipe[1], &dummy, 1) == -1 && errno != EAGAIN) {
            LOG_ERROR("Failed to write to notify_pipe for shutdown signal.");
        }
    }
    // Netlink thread will see global_shutdown_flag in its loop or on select timeout.
}


// Parses a single mapping string "if_name:vrf_name:if_ip"
// Returns 0 on success, -1 on failure.
// Populates the provided if_vrf_map_t struct.
// IMPORTANT: map_str will be modified by strtok_r. Pass a mutable copy.
int parse_mapping_string(char *map_str_copy, if_vrf_map_t *map_entry) {
    char *token;
    char *saveptr;

    // if_name
    token = strtok_r(map_str_copy, ":", &saveptr);
    if (!token) { LOG_ERROR("Invalid map string format (missing if_name): %s", map_str_copy); return -1; }
    strncpy(map_entry->if_name, token, IFNAMSIZ - 1);
    map_entry->if_name[IFNAMSIZ - 1] = '\0';

    // vrf_name
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) { LOG_ERROR("Invalid map string format (missing vrf_name for if %s): %s", map_entry->if_name, map_str_copy); return -1; }
    strncpy(map_entry->vrf_name, token, MAX_VRF_NAME_LEN - 1);
    map_entry->vrf_name[MAX_VRF_NAME_LEN - 1] = '\0';

    // if_ip
    token = strtok_r(NULL, ":", &saveptr);
    if (!token) { LOG_ERROR("Invalid map string format (missing if_ip for if %s, vrf %s): %s", map_entry->if_name, map_entry->vrf_name, map_str_copy); return -1; }
    strncpy(map_entry->if_ip_str, token, sizeof(map_entry->if_ip_str) - 1);
    map_entry->if_ip_str[sizeof(map_entry->if_ip_str) - 1] = '\0';

    if (inet_pton(AF_INET, map_entry->if_ip_str, &map_entry->if_ip) != 1) {
        LOG_ERROR("Invalid IP address '%s' in mapping for interface %s.", map_entry->if_ip_str, map_entry->if_name);
        return -1;
    }
    map_entry->listen_fd = -1; // Should be initialized by caller or subsequent setup
    map_entry->vrf_idx = -1;   // Should be initialized by caller or subsequent setup
    strncpy(map_entry->original_map_str, map_str_copy, sizeof(map_entry->original_map_str) -1 ); // Store original for comparison
    map_entry->original_map_str[sizeof(map_entry->original_map_str)-1] = '\0';

    return 0;
}


// Parses the configuration file for interface-VRF mappings
// Populates temp_maps array and updates temp_num_maps.
// Returns 0 on success, -1 on critical error (e.g., file not open).
int parse_config_file(const char *filepath, if_vrf_map_t temp_maps[], int *temp_num_maps, int max_maps) {
    LOG_INFO("Parsing mapping configuration file: %s", filepath);
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        LOG_ERROR("Failed to open configuration file: %s", filepath);
        return -1; // Critical: cannot open file
    }

    char line_buffer[512]; // Buffer for reading lines
    int line_num = 0;
    *temp_num_maps = 0;

    while (fgets(line_buffer, sizeof(line_buffer), fp)) {
        line_num++;

        char original_line_for_map_str[512]; // Store the line before strtok_r modifies it
        strncpy(original_line_for_map_str, line_buffer, sizeof(original_line_for_map_str)-1);
        original_line_for_map_str[sizeof(original_line_for_map_str)-1] = '\0';
        original_line_for_map_str[strcspn(original_line_for_map_str, "\n\r")] = 0;


        // Remove newline characters at the end
        line_buffer[strcspn(line_buffer, "\n\r")] = 0;

        // Trim leading whitespace
        char *trimmed_line = line_buffer;
        while (isspace((unsigned char)*trimmed_line)) {
            trimmed_line++;
        }

        // Skip empty lines and comments (lines starting with '#')
        if (*trimmed_line == '\0' || *trimmed_line == '#') {
            continue;
        }

        if (*temp_num_maps >= max_maps) {
            LOG_ERROR("Maximum number of interface-VRF mappings (%d) reached from config file at line %d. Ignoring further entries.", max_maps, line_num);
            break;
        }

        char parse_line_copy[512];
        strncpy(parse_line_copy, trimmed_line, sizeof(parse_line_copy)-1);
        parse_line_copy[sizeof(parse_line_copy)-1] = '\0';


        if (parse_mapping_string(parse_line_copy, &temp_maps[*temp_num_maps]) == 0) {
            // Store the original trimmed line (before strtok_r) for comparison logic
            strncpy(temp_maps[*temp_num_maps].original_map_str, trimmed_line, sizeof(temp_maps[*temp_num_maps].original_map_str) -1 );
            temp_maps[*temp_num_maps].original_map_str[sizeof(temp_maps[*temp_num_maps].original_map_str)-1] = '\0';

            LOG_DEBUG("Config File Line %d: Parsed mapping Iface '%s' -> VRF '%s' (IP %s)", line_num,
                     temp_maps[*temp_num_maps].if_name,
                     temp_maps[*temp_num_maps].vrf_name,
                     temp_maps[*temp_num_maps].if_ip_str);
            (*temp_num_maps)++;
        } else {
            LOG_WARN("Skipping invalid mapping on line %d of config file: %s", line_num, line_buffer); // Log original line_buffer for context
        }
    }

    fclose(fp);
    LOG_INFO("Finished parsing config file '%s'. Found %d valid mappings.", filepath, *temp_num_maps);
    return 0;
}


// Parses -m command line arguments
int process_cli_mappings(int argc, char *argv[], if_vrf_map_t maps[], int* num_maps, int max_maps) {
    int opt;
    optind = 1;
    *num_maps = 0;

    while ((opt = getopt(argc, argv, ":m:")) != -1) {
        if (opt == 'm') {
            if (*num_maps >= max_maps) {
                LOG_ERROR("Maximum number of interface-VRF mappings (%d) reached via -m. Ignoring further.", max_maps);
                continue;
            }
            char *if_details_arg = optarg;
            char if_details_copy[256];
            strncpy(if_details_copy, if_details_arg, sizeof(if_details_copy) -1);
            if_details_copy[sizeof(if_details_copy)-1] = '\0';

            if(parse_mapping_string(if_details_copy, &maps[*num_maps]) == 0) {
                 // For CLI maps, the original_map_str can be the optarg itself if needed for consistency,
                 // or just the parsed components. Here, we'll reconstruct it for consistency.
                 snprintf(maps[*num_maps].original_map_str, sizeof(maps[*num_maps].original_map_str),
                          "%s:%s:%s", maps[*num_maps].if_name, maps[*num_maps].vrf_name, maps[*num_maps].if_ip_str);

                 LOG_INFO("CLI Mapping: Iface '%s' -> VRF '%s' (IP %s)", maps[*num_maps].if_name, maps[*num_maps].vrf_name, maps[*num_maps].if_ip_str);
                (*num_maps)++;
            } else {
                LOG_WARN("Skipping invalid -m mapping string: %s", if_details_arg);
            }
        }
    }
    return 0;
}

// Helper to set up a listening socket for a given interface map entry
int setup_if_map_socket(if_vrf_map_t *map_entry) {
    if (!map_entry) return -1;

    if (map_entry->listen_fd != -1) {
        LOG_WARN("Interface map for %s already has a socket FD %d. Closing first.", map_entry->if_name, map_entry->listen_fd);
        close(map_entry->listen_fd);
        map_entry->listen_fd = -1;
    }

    map_entry->listen_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (map_entry->listen_fd < 0) {
        LOG_ERROR("Failed to create client listening socket for interface %s (%s)", map_entry->if_name, map_entry->if_ip_str);
        return -1;
    }

    int broadcast_enable = 1;
    if (setsockopt(map_entry->listen_fd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        LOG_ERROR("Failed to set SO_BROADCAST on client listening socket for %s", map_entry->if_name);
        close(map_entry->listen_fd);
        map_entry->listen_fd = -1;
        return -1;
    }

    int reuse_addr_enable = 1;
    if (setsockopt(map_entry->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr_enable, sizeof(reuse_addr_enable)) < 0) {
        LOG_ERROR("Failed to set SO_REUSEADDR on client listening socket for %s", map_entry->if_name);
    }

    struct sockaddr_in client_bind_addr;
    memset(&client_bind_addr, 0, sizeof(client_bind_addr));
    client_bind_addr.sin_family = AF_INET;
    client_bind_addr.sin_port = htons(DHCP_SERVER_PORT);
    client_bind_addr.sin_addr.s_addr = map_entry->if_ip.s_addr;

    if (bind(map_entry->listen_fd, (struct sockaddr *)&client_bind_addr, sizeof(client_bind_addr)) < 0) {
        LOG_ERROR("Failed to bind client listening socket to %s:%d for interface %s", map_entry->if_ip_str, DHCP_SERVER_PORT, map_entry->if_name);
        close(map_entry->listen_fd);
        map_entry->listen_fd = -1;
        return -1;
    }
    LOG_INFO("Client listening socket for interface %s created (FD: %d), bound to %s:%d",
             map_entry->if_name, map_entry->listen_fd, map_entry->if_ip_str, DHCP_SERVER_PORT);
    return 0;
}


// Reloads interface mappings from the config file
int reload_interface_mappings() {
    if (!config_file_path) {
        LOG_WARN("SIGHUP received but no config file path specified. Cannot reload mappings.");
        return -1;
    }
    LOG_INFO("Reloading interface mappings from: %s", config_file_path);

    if_vrf_map_t temp_new_maps[MAX_IF_VRF_MAPS];
    int temp_num_new_maps = 0;

    if (parse_config_file(config_file_path, temp_new_maps, &temp_num_new_maps, MAX_IF_VRF_MAPS) != 0) {
        LOG_ERROR("Failed to parse config file %s during reload. Mappings unchanged.", config_file_path);
        return -1;
    }

    if_vrf_map_t updated_maps[MAX_IF_VRF_MAPS];
    int updated_num_maps = 0;
    int old_map_processed[MAX_IF_VRF_MAPS] = {0}; // Track which old maps are carried over or modified

    // Iterate through new maps from config file
    for (int i = 0; i < temp_num_new_maps; ++i) {
        int found_match_in_old = -1;
        for (int j = 0; j < num_if_vrf_maps; ++j) {
            // Match based on if_name and vrf_name
            if (strcmp(temp_new_maps[i].if_name, if_vrf_maps[j].if_name) == 0 &&
                strcmp(temp_new_maps[i].vrf_name, if_vrf_maps[j].vrf_name) == 0) {
                found_match_in_old = j;
                break;
            }
        }

        if (updated_num_maps >= MAX_IF_VRF_MAPS) { LOG_WARN("Max mappings reached during reload build. Some new maps ignored."); break;}

        if (found_match_in_old != -1) { // Map existed
            old_map_processed[found_match_in_old] = 1; // Mark as processed
            // Check if IP address changed
            if (strcmp(temp_new_maps[i].if_ip_str, if_vrf_maps[found_match_in_old].if_ip_str) != 0) {
                LOG_INFO("IP changed for map %s:%s (Old: %s, New: %s). Recreating socket.",
                         temp_new_maps[i].if_name, temp_new_maps[i].vrf_name,
                         if_vrf_maps[found_match_in_old].if_ip_str, temp_new_maps[i].if_ip_str);
                if (if_vrf_maps[found_match_in_old].listen_fd != -1) {
                    close(if_vrf_maps[found_match_in_old].listen_fd);
                }
                updated_maps[updated_num_maps] = temp_new_maps[i]; // Copy new data
                updated_maps[updated_num_maps].listen_fd = -1; // Mark for new socket creation
            } else {
                // Unchanged map, copy it as is (preserving listen_fd and vrf_idx)
                LOG_DEBUG("Map %s:%s unchanged. Preserving.", temp_new_maps[i].if_name, temp_new_maps[i].vrf_name);
                updated_maps[updated_num_maps] = if_vrf_maps[found_match_in_old];
            }
        } else { // New map
            LOG_INFO("New map from config: %s:%s:%s. Adding.", temp_new_maps[i].if_name, temp_new_maps[i].vrf_name, temp_new_maps[i].if_ip_str);
            updated_maps[updated_num_maps] = temp_new_maps[i];
            updated_maps[updated_num_maps].listen_fd = -1; // Mark for new socket creation
        }
        updated_num_maps++;
    }

    // Close sockets for maps that were in old config but not in new (removed)
    for (int i = 0; i < num_if_vrf_maps; ++i) {
        if (!old_map_processed[i] && if_vrf_maps[i].listen_fd != -1) {
            LOG_INFO("Map %s:%s removed. Closing socket FD %d.", if_vrf_maps[i].if_name, if_vrf_maps[i].vrf_name, if_vrf_maps[i].listen_fd);
            close(if_vrf_maps[i].listen_fd);
        }
    }

    // Update the global maps array
    memcpy(if_vrf_maps, updated_maps, updated_num_maps * sizeof(if_vrf_map_t));
    num_if_vrf_maps = updated_num_maps;
    // Clear out any remaining old entries beyond the new count, just in case
    if (num_if_vrf_maps < MAX_IF_VRF_MAPS) {
         memset(&if_vrf_maps[num_if_vrf_maps], 0, (MAX_IF_VRF_MAPS - num_if_vrf_maps) * sizeof(if_vrf_map_t));
    }


    // Re-create sockets for new or modified IP mappings and re-resolve VRF indexes
    for (int i = 0; i < num_if_vrf_maps; ++i) {
        if (if_vrf_maps[i].listen_fd == -1) { // Needs new socket
            if (setup_if_map_socket(&if_vrf_maps[i]) != 0) {
                LOG_ERROR("Failed to setup socket for (re)loaded map %s. It will be inactive.", if_vrf_maps[i].if_name);
            }
        }
    }

    resolve_vrf_indices_for_maps(); // Re-resolve all VRF indexes
    LOG_INFO("Interface mappings reloaded. Active mappings: %d", num_if_vrf_maps);
    if (notify_pipe[1] != -1) { // Notify dispatch thread to rebuild its fd_set
        char dummy = 'R'; // R for Rebuild
        if(write(notify_pipe[1], &dummy, 1) == -1 && errno != EAGAIN) {
            LOG_ERROR("Failed to write to notify_pipe for config reload.");
        }
    }
    return 0;
}


int main(int argc, char *argv[]) {
    LOG_INFO("Kea Per-VRF DHCP Service Orchestrator starting...");

    pthread_mutex_init(&vrf_list_mutex, NULL);
    pthread_mutex_init(&map_list_mutex, NULL);

    if (pipe(notify_pipe) == -1) {
        LOG_ERROR("Failed to create notify_pipe. Exiting.");
        return EXIT_FAILURE;
    }
    // Make pipe non-blocking for writer to avoid blocking signal handler or main thread if pipe is full
    // (though only one byte is written, so less likely an issue here)
    // fcntl(notify_pipe[0], F_SETFL, O_NONBLOCK);
    // fcntl(notify_pipe[1], F_SETFL, O_NONBLOCK);


    // Parse command line options
    int opt_c;
    opterr = 0;
    while((opt_c = getopt(argc, argv, "c:m:")) != -1) {
        if (opt_c == 'c') {
            config_file_path = strdup(optarg);
            if (!config_file_path) { LOG_ERROR("strdup failed for config_file_path"); return EXIT_FAILURE; }
            use_config_file_mappings = 1;
            break;
        } else if (opt_c == 'm') {
        } else if (opt_c == '?') {
        }
    }
    opterr = 1;

    if (use_config_file_mappings) {
        LOG_INFO("Configuration file specified: %s. Mappings will be loaded from this file.", config_file_path);
        optind = 1;
        int temp_opt; int m_opt_present = 0;
        while((temp_opt = getopt(argc, argv, "c:m:")) != -1) {
            if (temp_opt == 'm') { m_opt_present = 1; break; }
        }
        if (m_opt_present) LOG_WARN("Config file (-c) specified; -m options ignored for initial setup.");

        pthread_mutex_lock(&map_list_mutex);
        if (parse_config_file(config_file_path, if_vrf_maps, &num_if_vrf_maps, MAX_IF_VRF_MAPS) != 0) {
             LOG_WARN("Failed to load initial mappings from config file %s. Relay may not function until SIGHUP reload.", config_file_path);
             num_if_vrf_maps = 0;
        }
        pthread_mutex_unlock(&map_list_mutex);

    } else {
        pthread_mutex_lock(&map_list_mutex);
        process_cli_mappings(argc, argv, if_vrf_maps, &num_if_vrf_maps, MAX_IF_VRF_MAPS);
        pthread_mutex_unlock(&map_list_mutex);
        if (num_if_vrf_maps == 0) {
            LOG_WARN("No client interface to VRF mappings provided via -m. DHCP relay will not function unless a config file is specified and loaded via SIGHUP.");
        }
    }

    signal(SIGINT, app_signal_handler);  // Use app_signal_handler for graceful shutdown
    signal(SIGTERM, app_signal_handler); // Use app_signal_handler for graceful shutdown
    signal(SIGHUP, sighup_handler);

    struct stat st = {0};
    if (stat(KEA_CONFIG_DIR, &st) == -1) {
        if (mkdir(KEA_CONFIG_DIR, 0755) == -1 && errno != EEXIST) {
             LOG_ERROR("Failed to create Kea config directory %s", KEA_CONFIG_DIR);
             return EXIT_FAILURE;
        }
    }

    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (netlink_fd < 0) {
        LOG_ERROR("Netlink socket creation failed. Dynamic VRF add/delete disabled.");
    } else {
        struct sockaddr_nl nl_addr = {0};
        nl_addr.nl_family = AF_NETLINK;
        nl_addr.nl_groups = RTMGRP_LINK;
        if (bind(netlink_fd, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) < 0) {
            LOG_ERROR("Netlink bind failed. Dynamic VRF add/delete disabled.");
            close(netlink_fd); netlink_fd = -1;
        } else {
            LOG_INFO("Netlink socket for VRF monitoring created (FD: %d).", netlink_fd);
        }
    }

    discover_vrfs();
    num_vrfs = 0;
    for (int i = 0; i < discovered_vrf_count; ++i) {
        if (num_vrfs >= MAX_VRFS) { LOG_WARN("MAX_VRFS limit reached. Ignoring further VRFs."); break; }
        vrf_instance_t *current_vrf = &vrf_instances[num_vrfs];
        memset(current_vrf, 0, sizeof(vrf_instance_t));
        current_vrf->kea_comm_fd = -1;
        strncpy(current_vrf->name, discovered_vrf_names[i], MAX_VRF_NAME_LEN - 1);
        current_vrf->name[MAX_VRF_NAME_LEN - 1] = '\0';
        LOG_INFO("Processing initially discovered VRF: %s", current_vrf->name);
        snprintf(current_vrf->ns_name, sizeof(current_vrf->ns_name), "%s_ns", current_vrf->name);
        snprintf(current_vrf->veth_host, IFNAMSIZ, "v%.8s_h", current_vrf->name);
        cleanup_vrf_instance(current_vrf);
        if (setup_namespace_for_vrf(current_vrf, num_vrfs) == 0 &&
            launch_kea_in_namespace(current_vrf, num_vrfs) == 0 &&
            setup_kea_communication_socket(current_vrf) == 0) {
            LOG_INFO("Successfully set up initial VRF: %s", current_vrf->name);
            num_vrfs++;
        } else {
            LOG_ERROR("Failed to setup initial VRF %s.", current_vrf->name);
            cleanup_vrf_instance(current_vrf);
        }
    }

    pthread_mutex_lock(&map_list_mutex);
    pthread_mutex_lock(&vrf_list_mutex);
    resolve_vrf_indices_for_maps();
    pthread_mutex_unlock(&vrf_list_mutex);
    pthread_mutex_unlock(&map_list_mutex);

    pthread_mutex_lock(&map_list_mutex);
    for (int i = 0; i < num_if_vrf_maps; ++i) {
        if(setup_if_map_socket(&if_vrf_maps[i]) != 0) {
            LOG_ERROR("Failed to setup listening socket for map %s:%s:%s. This map will be inactive.",
                if_vrf_maps[i].if_name, if_vrf_maps[i].vrf_name, if_vrf_maps[i].if_ip_str);
        }
    }
    pthread_mutex_unlock(&map_list_mutex);

    // Create threads
    pthread_t dispatch_tid, netlink_tid;
    if (pthread_create(&dispatch_tid, NULL, dispatch_thread_func, NULL) != 0) {
        LOG_ERROR("Failed to create packet dispatch thread. Exiting.");
        // Perform cleanup before exiting
        goto cleanup_and_exit;
    }
    if (netlink_fd != -1) { // Only create netlink thread if socket is valid
        if (pthread_create(&netlink_tid, NULL, netlink_thread_func, NULL) != 0) {
            LOG_ERROR("Failed to create netlink monitoring thread. Continuing without dynamic VRF updates.");
            // Not necessarily fatal, main dispatch can continue. Mark netlink_fd as unusable.
            close(netlink_fd);
            netlink_fd = -1;
        }
    } else {
        LOG_WARN("Netlink socket not available, Netlink monitoring thread will not be started.");
    }

    // Main thread loop for SIGHUP and shutdown signal checking
    LOG_INFO("Main thread entering monitoring loop (SIGHUP, shutdown).");
    while(!global_shutdown_flag) {
        sleep(1); // Check flags periodically
        if (reload_config_flag) {
            LOG_INFO("Main Thread: Reload config flag detected.");
            pthread_mutex_lock(&map_list_mutex); // Protect global if_vrf_maps
            pthread_mutex_lock(&vrf_list_mutex); // Protect global vrf_instances for resolve_vrf_indices
            reload_interface_mappings();
            pthread_mutex_unlock(&vrf_list_mutex);
            pthread_mutex_unlock(&map_list_mutex);
            reload_config_flag = 0;
            if (notify_pipe[1] != -1) { // Signal dispatch thread to rebuild its fd_set
                 char dummy = 'R';
                 if(write(notify_pipe[1], &dummy, 1) == -1 && errno != EAGAIN) {
                     LOG_ERROR("Main Thread: Failed to write to notify_pipe for config reload.");
                 }
            }
        }
    }

    LOG_INFO("Main thread: Shutdown signal received. Waiting for worker threads to exit...");
    pthread_join(dispatch_tid, NULL);
    LOG_INFO("Packet dispatch thread joined.");
    if (netlink_fd != -1 && netlink_tid) { // Check if netlink_tid was successfully created
         pthread_join(netlink_tid, NULL);
         LOG_INFO("Netlink monitoring thread joined.");
    }


cleanup_and_exit:
    // Final cleanup of global resources
    LOG_INFO("Performing final cleanup of VRFs and mappings...");
    pthread_mutex_lock(&map_list_mutex);
    for (int i = 0; i < num_if_vrf_maps; ++i) {
        if (if_vrf_maps[i].listen_fd != -1) {
            close(if_vrf_maps[i].listen_fd);
            if_vrf_maps[i].listen_fd = -1;
        }
    }
    pthread_mutex_unlock(&map_list_mutex);

    pthread_mutex_lock(&vrf_list_mutex);
    for (int i = 0; i < num_vrfs; ++i) {
        cleanup_vrf_instance(&vrf_instances[i]); // Stops Kea, closes kea_comm_fd, removes ns/veth
    }
    pthread_mutex_unlock(&vrf_list_mutex);

    if (config_file_path) free(config_file_path);
    if (netlink_fd != -1) close(netlink_fd);
    if (notify_pipe[0] != -1) close(notify_pipe[0]);
    if (notify_pipe[1] != -1) close(notify_pipe[1]);

    pthread_mutex_destroy(&vrf_list_mutex);
    pthread_mutex_destroy(&map_list_mutex);

    LOG_INFO("Orchestrator shut down gracefully.");
    return EXIT_SUCCESS;
}

[end of kea-vrf-orchestrator/src/orchestrator.c]

[end of kea-vrf-orchestrator/src/orchestrator.c]
