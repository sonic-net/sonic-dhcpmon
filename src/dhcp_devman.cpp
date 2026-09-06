/**
 * @file dhcp_devman.c
 *
 *  Device (interface) manager
 */

#include <assert.h>
#include <memory>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "dhcp_devman.h"


#include "dhcp_check_profile.h"  /** for setting check profile */
#include "util.h"          /** for db counter key generation */
#include <swss/subscriberstatetable.h>

bool dual_tor_mode = false;
bool dhcpv4_enabled = false;
bool dhcpv6_enabled = false;

in_addr vlan_ip = {0};
in6_addr vlan_ipv6_gua = {0};
in6_addr vlan_ipv6_lla = {0};

in_addr loopback_ip = {0};
in6_addr loopback_ipv6_gua = {0};

in_addr giaddr_ip = {0};
in_addr zero_ip = {0};
in6_addr giaddr_ipv6_gua = {0};
in6_addr zero_ipv6 = {0};

in_addr broadcast_ip = {.s_addr = INADDR_BROADCAST};

const char dhcpv6_multicast_ipv6_str[] = "ff02::1:2";
in6_addr dhcpv6_multicast_ipv6 = {0};

std::string downstream_ifname;
std::string mgmt_ifname;

std::string agg_dev_all;
std::string agg_dev_prefix;

std::unordered_map<std::string, std::string> vlan_map;
std::unordered_map<std::string, std::string> portchan_map;
std::unordered_map<std::string, std::unordered_set<std::string>> rev_vlan_map;
std::unordered_map<std::string, std::unordered_set<std::string>> rev_portchan_map;

std::unordered_map<std::string, dhcp_device_context_t *> intfs;

// dhcp check profile to use
dhcp_check_profile_t* dhcp_check_profile_ptr_rx;
dhcp_check_profile_t* dhcp_check_profile_ptr_tx;

// dhcpv6 check profile to use
dhcpv6_check_profile_t* dhcpv6_check_profile_ptr_rx;
dhcpv6_check_profile_t* dhcpv6_check_profile_ptr_tx;

/** dhcp_num_south_intf number of south interfaces */
static uint32_t dhcp_num_south_intf = 0;
/** dhcp_num_north_intf number of north interfaces */
static uint32_t dhcp_num_north_intf = 0;
/** dhcp_num_mgmt_intf number of mgmt interfaces */
static uint32_t dhcp_num_mgmt_intf = 0;

extern std::shared_ptr<swss::DBConnector> mConfigDbPtr;
extern std::shared_ptr<swss::DBConnector> mCountersDbPtr;

extern bool debug_on;

int dhcp_devman_add_intf(const char *name, char intf_type)
{
    int rv = -1;

    // Guard against duplicate -i* arguments referring to the same interface
    // (e.g. an interface that appears twice on the dhcpmon command line because
    // the supervisor template emitted it for two IP prefixes). Without this
    // check, the per-type counter is incremented twice (which trips the
    // `<= 1` asserts for -id/-im), and `intfs[name] = context;` below silently
    // overwrites and leaks the previously-registered device context. Treat
    // duplicates as a no-op success so the caller's error path does not fire.
    if (intfs.find(name) != intfs.end()) {
        syslog(LOG_INFO,
               "Ignoring duplicate -i%c for interface %s (already registered)",
               intf_type, name);
        return 0;
    }

    do {
        switch (intf_type) {
            case 'u':
                dhcp_num_north_intf++;
                break;
            case 'd':
                dhcp_num_south_intf++;
                assert(dhcp_num_south_intf <= 1);
                break;
            case 'm':
                dhcp_num_mgmt_intf++;
                assert(dhcp_num_mgmt_intf <= 1);
                break;
            default:
                break;
        }

        dhcp_device_context_t *context = dhcp_device_init(name, intf_type);
        if (context == NULL) {
            syslog(LOG_ALERT, "Failed to initialize device context for interface %s", name);
            break;
        }
        // we expect to have exactly 1 downstream interface and we need to know it's ip
        if (intf_type == 'd') {
            downstream_ifname = name;
            syslog(LOG_INFO, "Set downstream_ifname to %s", name);
            dhcp_device_get_ip(context, &vlan_ip, &vlan_ipv6_gua, &vlan_ipv6_lla);    
            syslog(LOG_INFO, "Set vlan_ip to %s", 
                   generate_addr_string((const uint8_t *)&vlan_ip, sizeof(vlan_ip)).c_str());
            syslog(LOG_INFO, "Set vlan_ipv6_gua to %s", 
                   generate_addr_string((const uint8_t *)&vlan_ipv6_gua, sizeof(vlan_ipv6_gua)).c_str());
            syslog(LOG_INFO, "Set vlan_ipv6_lla to %s", 
                   generate_addr_string((const uint8_t *)&vlan_ipv6_lla, sizeof(vlan_ipv6_lla)).c_str());
        }
        // we also expect exactly 1 mgmt interface and it's a physical interface
        if (intf_type == 'm') {
            mgmt_ifname = name;
            syslog(LOG_INFO, "Set mgmt_ifname to %s", name);
        }

        intfs[name] = context;
        syslog(LOG_INFO, "Add interface %s of type %c to intfs", name, intf_type);

        rv = 0;
    } while (0);

    return rv;
}

int dhcp_devman_setup_dual_tor_mode(const char *name)
{
    int rv = -1;

    do {
        // For dualtor, Loopback0 provides the relay identifier used toward DHCP servers.
        // Client-facing traffic still uses the downstream VLAN interface.

        dhcp_device_context_t loopback_context;
        if (strlen(name) >= sizeof(loopback_context.intf)) {
            syslog(LOG_ALERT, "Loopback interface name (%s) is too long", name);
            break;
        }

        strncpy(loopback_context.intf, name, sizeof(loopback_context.intf) - 1);
        loopback_context.intf[sizeof(loopback_context.intf) - 1] = '\0';
        syslog(LOG_INFO, "Retrieving ip addr for loopback interface (%s)", name);

        if (initialize_intf_mac_and_ip_addr(&loopback_context) < 0) {
            syslog(LOG_ALERT, "Failed to initialize mac/ip address for interface %s", name);
            break;
        }

        dhcp_device_get_ip(&loopback_context, &loopback_ip, &loopback_ipv6_gua, NULL);
        syslog(LOG_INFO, "Set loopback_ip to %s", 
               generate_addr_string((const uint8_t *)&loopback_ip, sizeof(loopback_ip)).c_str());
        syslog(LOG_INFO, "Set loopback_ipv6_gua to %s", 
               generate_addr_string((const uint8_t *)&loopback_ipv6_gua, sizeof(loopback_ipv6_gua)).c_str());
        dual_tor_mode = true;
        syslog(LOG_INFO, "Set dual_tor_mode to true");

        rv = 0;
    } while (0);

    return rv;
}

bool dhcp_devman_is_tracked_interface(const std::string &ifname)
{
    return intfs.find(ifname) != intfs.end() ||
           !dhcp_devman_get_parent_ifname(ifname).empty() ||
           ifname == mgmt_ifname;
}

/**
 * @code              update_vlan_mapping();
 * @brief             Update ethernet interface to vlan map, counter initilization is done later with info collected here
 *                    sample VLAN_MEMBER entry: VLAN_MEMBER|Vlan1000|Ethernet48
 * @param             none
 * @return            none
 */
static void update_vlan_mapping()
{
    syslog(LOG_INFO, "Updating vlan mapping from VLAN_MEMBER");
    auto match_pattern = std::string("VLAN_MEMBER|*");
    auto keys = mConfigDbPtr->keys(match_pattern);
    std::string all_ifname;
    std::string all_skipped_ifname;
    for (const auto &key : keys) {
        auto first = key.find_first_of('|');
        auto second = key.find_last_of('|');
        auto vlan = key.substr(first + 1, second - first - 1);
        auto ifname = key.substr(second + 1);
        if (intfs.find(vlan) == intfs.end()) {
            all_skipped_ifname += "<" + ifname + ", " + vlan + ">, ";
            continue;
        }
        vlan_map[ifname] = vlan;
        rev_vlan_map[vlan].insert(ifname);
        all_ifname += "<" + ifname + ", " + vlan + ">, ";
    }
    syslog(LOG_INFO, "Added vlan member interface mappings: %s", all_ifname.c_str());
    syslog(LOG_INFO, "Skipped vlan member interface mappings: %s", all_skipped_ifname.c_str());
}

/**
 * @code              update_portchannel_mapping();
 * @brief             Update ethernet interface to port-channel map, counter initialization is done later with info collected here
 *                    sample PORTCHANNEL_MEMBER entry: PORTCHANNEL_MEMBER|PortChannel101|Ethernet112
 * @param             none
 * @return            none
 */
static void update_portchannel_mapping()
{
    syslog(LOG_INFO, "Updating port-channel mapping from PORTCHANNEL_MEMBER");
    auto match_pattern = std::string("PORTCHANNEL_MEMBER|*");
    auto keys = mConfigDbPtr->keys(match_pattern);
    std::string all_ifname;
    std::string all_skipped_ifname;
    for (const auto &key : keys) {
        auto first = key.find_first_of('|');
        auto second = key.find_last_of('|');
        auto portchannel = key.substr(first + 1, second - first - 1);
        auto ifname = key.substr(second + 1);
        bool portchannel_is_context = intfs.find(portchannel) != intfs.end();
        bool portchannel_is_vlan_member = vlan_map.find(portchannel) != vlan_map.end();
        // Dual-ToR downlink counters require MUX attribution that is unavailable on a nested PortChannel.
        if (!portchannel_is_context && (!portchannel_is_vlan_member || dual_tor_mode)) {
            all_skipped_ifname += "<" + ifname + ", " + portchannel + ">, ";
            continue;
        }
        portchan_map[ifname] = portchannel;
        rev_portchan_map[portchannel].insert(ifname);
        all_ifname += "<" + ifname + ", " + portchannel + ">, ";
    }
    syslog(LOG_INFO, "Added port-channel member interface mappings: %s", all_ifname.c_str());
    syslog(LOG_INFO, "Skipped port-channel member interface mappings: %s", all_skipped_ifname.c_str());
}

int dhcp_devman_init()
{
    syslog(LOG_INFO, "Initializing dhcp device manager");

    // we expect exactly 1 downstream intf and at least 1 upstream intf
    if (dhcp_num_south_intf != 1) {
        syslog(LOG_ALERT, "Invalid number of interfaces, downlink/south %d, expect 1", dhcp_num_south_intf);
        return -1;
    }
    if (dhcp_num_north_intf == 0) {
        syslog(LOG_ALERT, "Invalid number of interfaces, uplink/north %d, expect more than 0", dhcp_num_north_intf);
        return -1;
    }

    // IPv4: VLAN IPv4 && (!DualToR || Loopback0 IPv4)
    // IPv6: VLAN GUA && VLAN LLA && (!DualToR || Loopback0 GUA)
    bool vlan_has_ipv4 = vlan_ip.s_addr != INADDR_ANY;
    bool vlan_has_ipv6_gua = !IN6_IS_ADDR_UNSPECIFIED(&vlan_ipv6_gua);
    bool vlan_has_ipv6_lla = !IN6_IS_ADDR_UNSPECIFIED(&vlan_ipv6_lla);
    bool loopback_has_ipv4 = loopback_ip.s_addr != INADDR_ANY;
    bool loopback_has_ipv6_gua = !IN6_IS_ADDR_UNSPECIFIED(&loopback_ipv6_gua);

    dhcpv4_enabled = vlan_has_ipv4 &&
                     (!dual_tor_mode || loopback_has_ipv4);
    dhcpv6_enabled = vlan_has_ipv6_gua &&
                     vlan_has_ipv6_lla &&
                     (!dual_tor_mode || loopback_has_ipv6_gua);

    if (!vlan_has_ipv4) {
        syslog(LOG_WARNING, "DHCPv4 monitoring disabled for %s: downstream IPv4 address is unavailable",
               downstream_ifname.c_str());
    }
    if (!vlan_has_ipv6_gua || !vlan_has_ipv6_lla) {
        syslog(LOG_WARNING, "DHCPv6 monitoring disabled for %s: downstream IPv6 GUA and LLA are required "
               "(GUA=%s, LLA=%s)", downstream_ifname.c_str(),
               vlan_has_ipv6_gua ? "available" : "missing",
               vlan_has_ipv6_lla ? "available" : "missing");
    }
    if (dual_tor_mode && !loopback_has_ipv4) {
        syslog(LOG_WARNING, "DHCPv4 monitoring disabled for %s: Dual-ToR loopback IPv4 address is unavailable",
               downstream_ifname.c_str());
    }
    if (dual_tor_mode && !loopback_has_ipv6_gua) {
        syslog(LOG_WARNING, "DHCPv6 monitoring disabled for %s: Dual-ToR loopback IPv6 GUA is unavailable",
               downstream_ifname.c_str());
    }
    if (!dhcpv4_enabled && !dhcpv6_enabled) {
        syslog(LOG_ALERT, "No address family satisfies monitoring requirements for %s", downstream_ifname.c_str());
        return -1;
    }
    syslog(LOG_INFO, "Enabled DHCP monitoring families for %s: IPv4=%s, IPv6=%s",
           downstream_ifname.c_str(), dhcpv4_enabled ? "true" : "false", dhcpv6_enabled ? "true" : "false");

    giaddr_ip = dual_tor_mode ? loopback_ip : vlan_ip;
    giaddr_ipv6_gua = dual_tor_mode ? loopback_ipv6_gua : vlan_ipv6_gua;
    inet_pton(AF_INET6, dhcpv6_multicast_ipv6_str, &dhcpv6_multicast_ipv6);
    syslog(LOG_INFO, "Set giaddr_ip to %s", generate_addr_string((const uint8_t *)&giaddr_ip, sizeof(in_addr)).c_str());
    syslog(LOG_INFO, "Set giaddr_ipv6_gua to %s", generate_addr_string((const uint8_t *)&giaddr_ipv6_gua, sizeof(in6_addr)).c_str());
    syslog(LOG_INFO, "Set dhcpv6_multicast_ipv6 to %s", generate_addr_string((const uint8_t *)&dhcpv6_multicast_ipv6, sizeof(in6_addr)).c_str());

    // set dhcp check profile pointers to first relay (T0/M0)
    dhcp_check_profile_ptr_rx = &dhcp_check_profile_first_relay_rx;
    dhcp_check_profile_ptr_tx = &dhcp_check_profile_first_relay_tx;
    syslog(LOG_INFO, "Set dhcp_check_profile to be first relay profiles");

    // set dhcpv6 check profile pointers to relay (T0/M0/Mx)
    dhcpv6_check_profile_ptr_rx = &dhcpv6_check_profile_relay_rx;
    dhcpv6_check_profile_ptr_tx = &dhcpv6_check_profile_relay_tx;
    syslog(LOG_INFO, "Set dhcpv6_check_profile to be relay profiles");

    agg_dev_all = "Agg-" + downstream_ifname;
    agg_dev_prefix = agg_dev_all + "-";

    // PortChannel members depend on VLAN mappings to recognize a PortChannel under a monitored VLAN.
    update_vlan_mapping();
    update_portchannel_mapping();

    syslog(LOG_INFO, "Dhcp device manager initialized successfully");

    return 0;
}

void dhcp_devman_free()
{
    dhcpv4_enabled = false;
    dhcpv6_enabled = false;
    vlan_map.clear();
    portchan_map.clear();
    for (const auto &[ifname, context] : intfs) {
        dhcp_device_free(context);
    }
    intfs.clear();
}

static constexpr unsigned int MAX_CONTEXT_DEPTH = 3;

std::string dhcp_devman_get_parent_ifname(const std::string &ifname)
{
    if (intfs.find(ifname) != intfs.end()) {
        return "";
    }
    const auto vlan = vlan_map.find(ifname);
    if (vlan != vlan_map.end() && ifname != vlan->second) {
        return vlan->second;
    }
    const auto port_channel = portchan_map.find(ifname);
    if (port_channel != portchan_map.end() && ifname != port_channel->second) {
        return port_channel->second;
    }
    return "";
}

/**
 * @code get_device_context(ifname, depth);
 *
 * @brief Follow parent mappings until reaching a tracked input interface
 *
 * @param ifname    Interface name to resolve
 * @param depth     Current parent traversal depth
 *
 * @return Tracked interface context, or NULL when no context is found
 */
static const dhcp_device_context_t *get_device_context(
    const std::string &ifname, unsigned int depth)
{
    if (depth > MAX_CONTEXT_DEPTH) {
        syslog_debug(LOG_WARNING, "Exceeded interface membership depth at %s", ifname.c_str());
        return NULL;
    }
    const auto iter = intfs.find(ifname);
    if (iter != intfs.end()) {
        return iter->second;
    }
    const std::string parent_ifname = dhcp_devman_get_parent_ifname(ifname);
    return parent_ifname.empty() ? NULL : get_device_context(parent_ifname, depth + 1);
}

const dhcp_device_context_t *dhcp_devman_get_device_context(const std::string &ifname)
{
    return get_device_context(ifname, 0);
}

std::string dhcp_devman_get_agg_counter_ifname(const std::string &ifname)
{
    const std::string parent_ifname = dhcp_devman_get_parent_ifname(ifname);
    return parent_ifname.empty() ? agg_dev_all :
           get_agg_counter_ifname(parent_ifname);
}

void dhcp_devman_print_all_status(dhcp_counters_type_t type)
{
    dhcp_device_print_status(agg_dev_all, type);
    for (const auto &[ifname, context] : intfs) {
        dhcp_device_print_status(ifname, type);
    }
}

void dhcp_devman_print_all_status_debug(dhcp_counters_type_t type)
{
    if (debug_on) {
        dhcp_devman_print_all_status(type);
    }
}