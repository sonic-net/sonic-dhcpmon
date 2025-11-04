/**
 * @file dhcp_devman.c
 *
 *  Device (interface) manager
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "dhcp_devman.h"

#include "sock_mgr.h"      /** for counter operations */
#include "util.h"          /** for db counter key generation */
#include <swss/subscriberstatetable.h>

#define MINIMUM_BUFFER_SZ 2024

bool dual_tor_mode = false;

in_addr vlan_ip = {0};
in6_addr vlan_ipv6_gua = {0};
in6_addr vlan_ipv6_lla = {0};

in_addr loopback_ip = {0};
in6_addr loopback_ipv6_gua = {0};
in6_addr loopback_ipv6_lla = {0};

in_addr giaddr_ip = {0};
in6_addr giaddr_ipv6 = {0};
in6_addr zero_ipv6 = {0};

std::string downstream_ifname;
std::string mgmt_ifname;

std::string agg_dev_all;
std::string agg_dev_prefix;

std::unordered_map<std::string, std::string> vlan_map;
std::unordered_map<std::string, std::string> portchan_map;
std::unordered_map<std::string, std::unordered_set<std::string>> rev_vlan_map;
std::unordered_map<std::string, std::unordered_set<std::string>> rev_portchan_map;

/** name to context struct map for all context interface only */
static std::unordered_map<std::string, dhcp_device_context_t *> intfs;

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
        if (intf_type == 'd') {
            downstream_ifname = name;
            syslog(LOG_INFO, "Set downstream_ifname to %s", name);
            dhcp_device_get_ip(context, &vlan_ip, &vlan_ipv6_gua, &vlan_ipv6_lla);    
            syslog(LOG_INFO, "Set vlan_ip to %s", 
                   generate_addr_string((uint8_t *)&vlan_ip, sizeof(vlan_ip)).c_str());
            syslog(LOG_INFO, "Set vlan_ipv6_gua to %s", 
                   generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(vlan_ipv6_gua)).c_str());
            syslog(LOG_INFO, "Set vlan_ipv6_lla to %s", 
                   generate_addr_string((uint8_t *)&vlan_ipv6_lla, sizeof(vlan_ipv6_lla)).c_str());
        }
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
        dhcp_device_get_ip(&loopback_context, &loopback_ip, &loopback_ipv6_gua, &loopback_ipv6_lla);
        syslog(LOG_INFO, "Set loopback_ip to %s", 
               generate_addr_string((uint8_t *)&loopback_ip, sizeof(loopback_ip)).c_str());
        syslog(LOG_INFO, "Set loopback_ipv6_gua to %s", 
               generate_addr_string((uint8_t *)&loopback_ipv6_gua, sizeof(loopback_ipv6_gua)).c_str());
        syslog(LOG_INFO, "Set loopback_ipv6_lla to %s", 
               generate_addr_string((uint8_t *)&loopback_ipv6_lla, sizeof(loopback_ipv6_lla)).c_str());

        dual_tor_mode = true;
        syslog(LOG_INFO, "Set dual_tor_mode to true");
        
        rv = 0;
    } while (0);

    return rv;
}


/**
 * @code                initialize_db_counters(ifname);
 * @brief               Initialize the counter in counters_db with interface name
 * @param ifname        interface name
 * @return              none
 */
static void initialize_db_counters(const std::string &ifname)
{
    std::string table_name;
    std::string init_value;

    syslog_debug(LOG_INFO, "Initialize DB counters for interface %s to be all 0", ifname.c_str());

    table_name = construct_counter_db_table_key(ifname, false);
    init_value = generate_json_string(NULL, DHCP_MESSAGE_TYPE_COUNT, db_counter_name);
    mCountersDbPtr->hset(table_name, "RX", init_value);
    mCountersDbPtr->hset(table_name, "TX", init_value);
    
    table_name = construct_counter_db_table_key(ifname, true);
    init_value = generate_json_string(NULL, DHCPV6_MESSAGE_TYPE_COUNT, db_counter_name_v6);
    mCountersDbPtr->hset(table_name, "RX", init_value);
    mCountersDbPtr->hset(table_name, "TX", init_value);
}

/**
 * @code              db_counters_initialized(ifname);
 * @brief             Check if the counter in counters_db is initialized for given interface name
 * @param ifname      interface name
 * @return            true if initialized, false otherwise
 */
static bool db_counters_initialized(const std::string &ifname)
{
    std::string table_name;
    std::string *field;

    table_name = construct_counter_db_table_key(ifname, false);
    field = mCountersDbPtr->hget(table_name, "RX").get();
    if (field == NULL || field->empty()) {
        return false;
    }
    field = mCountersDbPtr->hget(table_name, "TX").get();
    if (field == NULL || field->empty()) {
        return false;
    }

    table_name = construct_counter_db_table_key(ifname, true);
    field = mCountersDbPtr->hget(table_name, "RX").get();
    if (field == NULL || field->empty()) {
        return false;
    }
    field = mCountersDbPtr->hget(table_name, "TX").get();
    if (field == NULL || field->empty()) {
        return false;
    }

    return true;
}

/**
 * @code              initialize_all_counters(ifname, init_db);
 * @brief             Initialize both db counters (we do not for agg device) and cache counters for given interface name
 * @param ifname      interface name
 * @param init_db     whether to initialize db counters
 * @return            none
 */
static void initialize_all_counters(const std::string &ifname)
{
    syslog_debug(LOG_INFO, "Initialize DB counters for interface %s to be all 0", ifname.c_str());
    initialize_db_counters(ifname);
    sock_mgr_init_cache_counters(ifname, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);
}

/**
 * @code              all_counters_initialized(ifname);
 * @brief             Check if both db counters and cache counters are initialized for given interface name, cannot be used on agg device
 * @param ifname      interface name
 * @return            true if initialized, false otherwise
 */
static bool all_counters_initialized(const std::string &ifname)
{
    return db_counters_initialized(ifname) && sock_mgr_all_cache_counters_initialized(ifname);
}

/**
 * @code              update_vlan_mapping();
 * @brief             Update ethernet interface to vlan map, initialize counters for all vlan and vlan members, if they are in intfs
 *                    sample VLAN_MEMBER entry: VLAN_MEMBER|Vlan1000|Ethernet48
 * @param             none
 * @return            none
 */
static void update_vlan_mapping()
{
    syslog(LOG_INFO, "Updating vlan mapping from VLAN_MEMBER");
    auto match_pattern = std::string("VLAN_MEMBER|*");
    auto keys = mConfigDbPtr->keys(match_pattern);
    std::unordered_set<std::string> vlans;
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
        vlans.insert(vlan);
        initialize_all_counters(ifname);
    }
    syslog(LOG_INFO, "Added vlan member interface mappings: %s", all_ifname.c_str());
    syslog(LOG_INFO, "Skipped vlan member interface mappings: %s", all_skipped_ifname.c_str());
    for (const auto &ifname : vlans) {
        initialize_all_counters(ifname);
        sock_mgr_init_cache_counters(agg_dev_prefix + ifname, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);
    }
}

/**
 * @code              update_portchannel_mapping();
 * @brief             Update ethernet interface to port-channel map and initialize counters for all portchannels and its members, if they are in intfs
 *                    sample PORTCHANNEL_MEMBER entry: PORTCHANNEL_MEMBER|PortChannel101|Ethernet112
 * @param             none
 * @return            none
 */
static void update_portchannel_mapping()
{
    syslog(LOG_INFO, "Updating port-channel mapping from PORTCHANNEL_MEMBER");
    auto match_pattern = std::string("PORTCHANNEL_MEMBER|*");
    auto keys = mConfigDbPtr->keys(match_pattern);
    std::unordered_set<std::string> portchannels;
    std::string all_ifname;
    std::string all_skipped_ifname;
    for (const auto &key : keys) {
        auto first = key.find_first_of('|');
        auto second = key.find_last_of('|');
        auto portchannel = key.substr(first + 1, second - first - 1);
        auto ifname = key.substr(second + 1);
        if (intfs.find(portchannel) == intfs.end()) {
            all_skipped_ifname += "<" + ifname + ", " + portchannel + ">, ";
            continue;
        }
        portchan_map[ifname] = portchannel;
        rev_portchan_map[portchannel].insert(ifname);
        all_ifname += "<" + ifname + ", " + portchannel + ">, ";
        portchannels.insert(portchannel);
        initialize_all_counters(ifname);
    }
    syslog(LOG_INFO, "Added port-channel member interface mappings: %s", all_ifname.c_str());
    syslog(LOG_INFO, "Skipped port-channel member interface mappings: %s", all_skipped_ifname.c_str());
    for (const auto &ifname : portchannels) {
        initialize_all_counters(ifname);
        sock_mgr_init_cache_counters(agg_dev_prefix + ifname, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);
    }
}

int dhcp_devman_init(size_t snaplen)
{
    syslog(LOG_INFO, "Initializing dhcp device manager");

    if (dhcp_num_south_intf != 1) {
        syslog(LOG_ALERT, "Invalid number of interfaces, downlink/south %d, expect 1", dhcp_num_south_intf);
        return -1;
    }
    if (dhcp_num_north_intf == 0) {
        syslog(LOG_ALERT, "Invalid number of interfaces, uplink/north %d, expect more than 0", dhcp_num_north_intf);
        return -1;
    }

    giaddr_ip = dual_tor_mode ? loopback_ip : vlan_ip;
    giaddr_ipv6 = dual_tor_mode ? loopback_ipv6_gua : vlan_ipv6_gua;
    syslog(LOG_INFO, "Set giaddr_ip to %s", generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str());
    syslog(LOG_INFO, "Set giaddr_ipv6 to %s", generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str());

    agg_dev_all = "Agg-" + downstream_ifname;
    agg_dev_prefix = agg_dev_all + "-";

    if (snaplen < MINIMUM_BUFFER_SZ) {
        syslog(LOG_ALERT, "dhcp_device_start_capture: snap length is too low to capture DHCP options");
        return -1;
    }

    if (sock_mgr_init(snaplen) < 0) {
        syslog(LOG_ALERT, "Failed to initialize sock_map");
        return -1;
    }

    // vlan and its members, portchannel and its members are initialized regardless of whether they are in cmdline
    update_vlan_mapping();
    update_portchannel_mapping();

    for (const auto &itr : intfs) {
        // Now all vlan and portchannel related interfaces have entries in counters, now do the rest (uplink)
        if (!all_counters_initialized(itr.first)) {
            initialize_all_counters(itr.first);
        }
    }
    if (mgmt_ifname.size() > 0) {
        initialize_all_counters(mgmt_ifname);
    }
    sock_mgr_init_cache_counters(agg_dev_all, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);

    syslog(LOG_INFO, "Dhcp device manager initialized successfully");

    return 0;
}

void dhcp_devman_free()
{
    vlan_map.clear();
    portchan_map.clear();
    sock_mgr_free();
    for (const auto &[ifname, context] : intfs) {
        dhcp_device_free(context);
    }
    intfs.clear();
}

const dhcp_device_context_t *dhcp_devman_get_device_context(const std::string &ifname)
{
    const auto iter = intfs.find(ifname);
    if (iter != intfs.end()) {
        return iter->second;
    }
    const auto vlan = vlan_map.find(ifname);
    if (vlan != vlan_map.end() && ifname != vlan->second) {
        return dhcp_devman_get_device_context(vlan->second);
    }
    const auto port_channel = portchan_map.find(ifname);
    if (port_channel != portchan_map.end() && ifname != port_channel->second) {
        return dhcp_devman_get_device_context(port_channel->second);
    }
    return NULL;
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