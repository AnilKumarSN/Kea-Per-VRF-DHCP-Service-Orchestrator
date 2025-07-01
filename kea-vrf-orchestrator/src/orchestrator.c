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

// Basic logging macros
#define LOG_INFO(msg, ...) fprintf(stdout, "[INFO] " msg "\n", ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) fprintf(stderr, "[ERROR] (%s:%d:%s) " msg "\n", __FILE__, __LINE__, strerror(errno), ##__VA_ARGS__)
#define LOG_DEBUG(msg, ...) fprintf(stdout, "[DEBUG] " msg "\n", ##__VA_ARGS__)

#define MAX_VRFS 10
#define MAX_VRF_NAME_LEN 64
#define KEA_CONFIG_DIR "../config" // Relative to where orchestrator is run from (e.g., build/)
#define SCRIPT_DIR "../scripts"     // Relative to where orchestrator is run from

// Structure to hold VRF information
typedef struct {
    char name[MAX_VRF_NAME_LEN];
    char ns_name[MAX_VRF_NAME_LEN + 4]; // <vrf_name>_ns
    char veth_host[MAX_VRF_NAME_LEN + 6]; // veth_<vrf_name>_h
    char veth_ns[MAX_VRF_NAME_LEN + 5];   // veth_<vrf_name>_ns
    char veth_host_ip[16]; // e.g. 169.254.X.1
    char veth_ns_ip[16];   // e.g. 169.254.X.2
    pid_t kea4_pid;
    pid_t kea6_pid;
} vrf_instance_t;

vrf_instance_t vrf_instances[MAX_VRFS];
int num_vrfs = 0;

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


// Function to discover VRFs (simplified: reads from a predefined list for now)
// In a real system, this would parse `ip link show type vrf` or netlink messages
void discover_vrfs() {
    LOG_INFO("Discovering VRFs...");
// In a real system, this would parse `ip link show type vrf` or netlink messages
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
    // Using first 8 chars of VRF name for veth.
    snprintf(vrf->veth_host, sizeof(vrf->veth_host), "v%.8s_h", vrf->name);
    snprintf(vrf->veth_ns, sizeof(vrf->veth_ns), "v%.8s_ns", vrf->name);

    snprintf(vrf->veth_host_ip, sizeof(vrf->veth_host_ip), "169.254.%d.1", vrf_index +1);
    snprintf(vrf->veth_ns_ip, sizeof(vrf->veth_ns_ip), "169.254.%d.2", vrf_index +1);


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
    // 1. Opening raw sockets on relevant host interfaces OR host-side veths.
    // 2. Receiving DHCP packets.
    // 3. Identifying the source VRF (e.g., based on incoming interface or packet metadata).
    // 4. Forwarding packets to the appropriate Kea instance via its veth_ns_ip.
    // 5. Receiving replies from Kea instances on veth_host_ip.
    // 6. Forwarding replies back to the clients.

    // For now, just sleep to keep the orchestrator running
    while(1) {
        sleep(10);
        LOG_DEBUG("Heartbeat: Orchestrator running.");
        // Check status of Kea processes
        for (int i = 0; i < num_vrfs; ++i) {
            if (vrf_instances[i].kea4_pid > 0) {
                int status;
                pid_t result = waitpid(vrf_instances[i].kea4_pid, &status, WNOHANG);
                if (result == vrf_instances[i].kea4_pid) {
                    LOG_ERROR("Kea DHCPv4 for VRF %s (PID %d) has exited.", vrf_instances[i].name, vrf_instances[i].kea4_pid);
                    vrf_instances[i].kea4_pid = 0; // Mark as exited
                    // Potentially restart it
                } else if (result == -1) {
                     LOG_ERROR("Error waiting for Kea DHCPv4 for VRF %s (PID %d).", vrf_instances[i].name, vrf_instances[i].kea4_pid);
                }
            }
            // Add similar check for kea6_pid
        }
    }
}

void cleanup_vrf_instance(vrf_instance_t *vrf) {
    LOG_INFO("Cleaning up VRF instance: %s", vrf->name);

    // Kill Kea processes
    if (vrf->kea4_pid > 0) {
        LOG_INFO("Stopping Kea DHCPv4 (PID %d) for VRF %s", vrf->kea4_pid, vrf->name);
        kill(vrf->kea4_pid, SIGTERM);
        waitpid(vrf->kea4_pid, NULL, 0); // Wait for it to terminate
        vrf->kea4_pid = 0;
    }
    if (vrf->kea6_pid > 0) {
        // kill(vrf->kea6_pid, SIGTERM);
        // waitpid(vrf->kea6_pid, NULL, 0);
        // vrf->kea6_pid = 0;
    }

    // Delete veth pair (deleting one end deletes the pair)
    char *cmd_veth_del[] = {"ip", "link", "del", vrf->veth_host, NULL};
    if (run_command("ip", cmd_veth_del) != 0) {
        LOG_ERROR("Failed to delete veth %s. It might have been deleted already or namespace cleanup handled it.", vrf->veth_host);
    }

    // Delete network namespace
    char *cmd_netns_del[] = {"ip", "netns", "del", vrf->ns_name, NULL};
    if (run_command("ip", cmd_netns_del) != 0) {
        LOG_ERROR("Failed to delete namespace %s. It might be in use or already deleted.", vrf->ns_name);
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
        char kea_config_file[256];
        snprintf(kea_config_file, sizeof(kea_config_file), "%s/kea-dhcp4-%s.conf", KEA_CONFIG_DIR, vrf_instances[i].name);
        if (remove(kea_config_file) == 0) {
            LOG_INFO("Removed Kea config file: %s", kea_config_file);
        } else {
            LOG_DEBUG("Could not remove Kea config file: %s (may not exist)", kea_config_file);
        }
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
        strncpy(vrf_instances[num_vrfs].name, discovered_vrf_names[i], MAX_VRF_NAME_LEN -1);

        // Attempt cleanup first in case of previous unclean shutdown
        cleanup_vrf_instance(&vrf_instances[num_vrfs]);


        if (setup_namespace_for_vrf(&vrf_instances[num_vrfs], num_vrfs) == 0) {
            if (launch_kea_in_namespace(&vrf_instances[num_vrfs]) == 0) {
                num_vrfs++; // Increment only if both setup and launch are successful
            } else {
                LOG_ERROR("Failed to launch Kea for VRF %s. Cleaning up.", vrf_instances[num_vrfs].name);
                cleanup_vrf_instance(&vrf_instances[num_vrfs]);
            }
        } else {
            LOG_ERROR("Failed to setup namespace for VRF %s.", vrf_instances[num_vrfs].name);
            // No need to call cleanup here as setup_namespace might have partially failed
        }
    }

    if (num_vrfs == 0) {
        LOG_ERROR("Failed to set up any VRF instances. Exiting.");
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
