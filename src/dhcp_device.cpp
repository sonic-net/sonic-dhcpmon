/**
 * @file dhcp_device.cpp
 */

#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <libexplain/ioctl.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <syslog.h>

#include "dhcp_device.h"

#include "sock_mgr.h" /** for counter operations */
#include "util.h"     /** for generate_addr_string */

/** Counter print width */
#define DHCP_COUNTER_WIDTH  9

extern bool debug_on;

extern std::string agg_dev_all;
extern std::string agg_dev_prefix;

extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_vlan_map;
extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_portchan_map;

const std::string db_counter_name[DHCP_MESSAGE_TYPE_COUNT] = {
    "Unknown", "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform", "Bootp", "Malformed", "Dropped"
};

const std::string db_counter_name_v6[DHCPV6_MESSAGE_TYPE_COUNT] = {
    "Unknown", "Solicit", "Advertise", "Request", "Confirm", "Renew", "Rebind", "Reply", "Release",
    "Decline", "Reconfigure", "Information-Request", "Relay-Forward", "Relay-Reply", "Malformed", "Dropped"
};

/** Monitored DHCP message type */
const dhcp_message_type_t monitored_msgs[] = {
    DHCP_MESSAGE_TYPE_DISCOVER,
    DHCP_MESSAGE_TYPE_OFFER,
    DHCP_MESSAGE_TYPE_REQUEST,
    DHCP_MESSAGE_TYPE_ACK
};

/** Number of monitored DHCP message type */
uint8_t monitored_msg_sz = sizeof(monitored_msgs) / sizeof(*monitored_msgs);

/** Monitored DHCPv6 message type */
const dhcpv6_message_type_t monitored_v6_msgs[] = {
    DHCPV6_MESSAGE_TYPE_SOLICIT,
    DHCPV6_MESSAGE_TYPE_ADVERTISE,
    DHCPV6_MESSAGE_TYPE_REQUEST,
    DHCPV6_MESSAGE_TYPE_REPLY,
    DHCPV6_MESSAGE_TYPE_RELAY_FORW,
    DHCPV6_MESSAGE_TYPE_RELAY_REPL
};

/** Number of monitored DHCPv6 message type */
uint8_t monitored_v6_msg_sz = sizeof(monitored_v6_msgs) / sizeof(*monitored_v6_msgs);

/** counter type to description */
const char *counter_desc[DHCP_COUNTERS_COUNT] = {
    [DHCP_COUNTERS_CURRENT] = "Current",
    [DHCP_COUNTERS_SNAPSHOT] = "Snapshot",
    [DHCP_COUNTERS_CURRENT_V6] = "Current_V6",
    [DHCP_COUNTERS_SNAPSHOT_V6] = "Snapshot_V6",
};

/**
 * @code check_counter_not_transmitted(ifname, rx_sock, tx_sock, monitored_msgs, monitored_msg_cnt);
 * @brief Check if there are received DHCP messages that are not transmitted out
 *        of this interface/device using its counters.
 * @param ifname            interface name
 * @param rx_sock           rx socket
 * @param tx_sock           tx socket
 * @param monitored_msgs    array of monitored message types
 * @param monitored_msg_cnt number of monitored message types
 * @return                  true if there are received messages not transmitted out, false otherwise
 */
static bool check_counter_not_transmitted(const std::string &ifname, int rx_sock, int tx_sock, const int *monitored_msgs, size_t monitored_msg_cnt)
{
    const sock_info_t &rx_sock_info = sock_mgr_get_sock_info(rx_sock);
    const counter_t &rx_counters = rx_sock_info.all_counters.at(ifname);
    const counter_t &rx_counters_snapshot = rx_sock_info.all_counters_snapshot.at(ifname);

    const sock_info_t &tx_sock_info = sock_mgr_get_sock_info(tx_sock);
    const counter_t &tx_counters = tx_sock_info.all_counters.at(ifname);
    const counter_t &tx_counters_snapshot = tx_sock_info.all_counters_snapshot.at(ifname);
    for (size_t i = 0; i < monitored_msg_cnt; i++) {
        if (rx_counters.at(monitored_msgs[i]) > rx_counters_snapshot.at(monitored_msgs[i]) &&
            tx_counters.at(monitored_msgs[i]) <= tx_counters_snapshot.at(monitored_msgs[i])) {
            return true;
        }
    }
    return false;
}

/**
 * @code dhcp_device_check_positive_health(ifname);
 * @brief Check that DHCP relayed messages are being transmitted out of this interface/dev
 *        using its counters. The interface is positively healthy if there are DHCP message
 *        travelling through it.
 * @param ifname           interface name
 * @return                 DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
static dhcp_mon_status_t dhcp_device_check_positive_health(const std::string &ifname)
{
    return check_counter_not_transmitted(ifname, rx_sock, tx_sock, (const int *)monitored_msgs, monitored_msg_sz) ?
           DHCP_MON_STATUS_UNHEALTHY : DHCP_MON_STATUS_HEALTHY;
}

/**
 * @code dhcp_device_check_positive_health_v6(ifname);
 * @brief Check that DHCPv6 relayed messages are being transmitted out of this interface/dev
 *        using its counters. The interface is positively healthy if there are DHCPv6 message
 *        travelling through it.
 * @param ifname           interface name
 * @return                 DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
static dhcp_mon_status_t dhcp_device_check_positive_health_v6(const std::string &ifname)
{
   return  check_counter_not_transmitted(ifname, rx_sock_v6, tx_sock_v6, (const int *)monitored_v6_msgs, monitored_v6_msg_sz) ?
           DHCP_MON_STATUS_UNHEALTHY : DHCP_MON_STATUS_HEALTHY;
}

/**
 * @code check_counter_increased(ifname, sock, monitored_msgs, monitored_msg_cnt);
 *
 * @brief Check if the counter for given message types has increased
 *
 * @param ifname            interface name
 * @param sock              socket
 * @param monitored_msgs    array of monitored message types
 * @param monitored_msg_cnt number of monitored message types
 *
 * @return                  true if counter has increased, false otherwise
 */
static bool check_counter_increased(const std::string &ifname, int sock, const int *monitored_msgs, size_t monitored_msg_cnt)
{
    const sock_info_t &sock_info = sock_mgr_get_sock_info(sock);
    const counter_t &counters = sock_info.all_counters.at(ifname);
    const counter_t &counters_snapshot = sock_info.all_counters_snapshot.at(ifname);

    for (size_t i = 0; i < monitored_msg_cnt; i++) {
        if (counters.at(monitored_msgs[i]) > counters_snapshot.at(monitored_msgs[i])) {
            return true;
        }
    }
    return false;
}

/**
 * @code dhcp_device_check_negative_health(ifname);
 *
 * @brief Check that DHCP relayed messages are NOT being transmitted out of this interface/dev
 *        using its counters. The interface is negatively healthy if there are NO DHCP message
 *        travelling through it.
 *
 * @param ifname           interface name
 *
 * @return                 DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
static dhcp_mon_status_t dhcp_device_check_negative_health(const std::string &ifname)
{
    return check_counter_increased(ifname, tx_sock, (const int *)monitored_msgs, monitored_msg_sz) ?
           DHCP_MON_STATUS_UNHEALTHY : DHCP_MON_STATUS_HEALTHY;
}

/**
 * @code dhcp_device_check_negative_health_v6(ifname);
 *
 * @brief Check that DHCPv6 relayed messages are NOT being transmitted out of this interface/dev
 *        using its counters. The interface is negatively healthy if there are NO DHCPv6 message
 *        travelling through it.
 *
 * @param ifname           interface name
 *
 * @return                 DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
static dhcp_mon_status_t dhcp_device_check_negative_health_v6(const std::string &ifname)
{
    return check_counter_increased(ifname, tx_sock_v6, (const int *)monitored_v6_msgs, monitored_v6_msg_sz) ?
           DHCP_MON_STATUS_UNHEALTHY : DHCP_MON_STATUS_HEALTHY;
}

/**
 * @code check_counters_delta_expected(ifname, other_ifname, sock, ratio, monitored_msgs, monitored_msg_cnt);
 * @brief Check if the delta of counters between current and snapshot for given message types
 *        match expectation between two interfaces with a given ratio.
 * @param ifname            interface name
 * @param other_ifname      other interface name
 * @param sock              socket
 * @param ratio             expected ratio between two interfaces, ratio = other_ifname / ifname
 * @param monitored_msgs    array of monitored message types
 * @param monitored_msg_cnt number of monitored message types
 * @return                  true if deltas are equal with given ratio, false otherwise
 */
static bool check_counters_delta_expected(const std::string &ifname, const std::string &other_ifname, int sock,
                                         uint8_t ratio, const int *monitored_msgs, size_t monitored_msg_cnt)
{
    const sock_info_t &sock_info = sock_mgr_get_sock_info(sock);
    const counter_t &counters = sock_info.all_counters.at(ifname);
    const counter_t &counters_snapshot = sock_info.all_counters_snapshot.at(ifname);
    const counter_t &other_counters = sock_info.all_counters.at(other_ifname);
    const counter_t &other_counters_snapshot = sock_info.all_counters_snapshot.at(other_ifname);

    for (size_t i = 0; i < monitored_msg_cnt; i++) {
        uint64_t delta = counters.at(monitored_msgs[i]) - counters_snapshot.at(monitored_msgs[i]);
        uint64_t other_delta = other_counters.at(monitored_msgs[i]) - other_counters_snapshot.at(monitored_msgs[i]);
        if (delta * ratio != other_delta) {
            return false;
        }
    }
    return true;
}

static dhcp_mon_status_t dhcp_device_check_agg_equal_rx(const std::string &ifname)
{
    std::string agg_ifname = agg_dev_prefix + ifname;
    return check_counters_delta_expected(ifname, agg_ifname, rx_sock, 1, (const int *)monitored_msgs, monitored_msg_sz) ?
           DHCP_MON_STATUS_HEALTHY : DHCP_MON_STATUS_UNHEALTHY;
}

static dhcp_mon_status_t dhcp_device_check_agg_equal_tx(const std::string &ifname)
{
    std::string agg_ifname = agg_dev_prefix + ifname;
    return check_counters_delta_expected(ifname, agg_ifname, tx_sock, 1, (const int *)monitored_msgs, monitored_msg_sz) ?
           DHCP_MON_STATUS_HEALTHY : DHCP_MON_STATUS_UNHEALTHY;
}

static dhcp_mon_status_t dhcp_device_check_agg_equal_rx_v6(const std::string &ifname)
{
    std::string agg_ifname = agg_dev_prefix + ifname;
    return check_counters_delta_expected(ifname, agg_ifname, rx_sock_v6, 1, (const int *)monitored_v6_msgs, monitored_v6_msg_sz) ?
           DHCP_MON_STATUS_HEALTHY : DHCP_MON_STATUS_UNHEALTHY;
}

static dhcp_mon_status_t dhcp_device_check_agg_equal_tx_v6(const std::string &ifname)
{
    std::string agg_ifname = agg_dev_prefix + ifname;
    return check_counters_delta_expected(ifname, agg_ifname, tx_sock_v6, 1, (const int *)monitored_v6_msgs, monitored_v6_msg_sz) ?
           DHCP_MON_STATUS_HEALTHY : DHCP_MON_STATUS_UNHEALTHY;
}

static dhcp_mon_status_t dhcp_device_check_agg_multiple_rx(const std::string &ifname)
{
    std::string agg_ifname = agg_dev_prefix + ifname;
    return check_counters_delta_expected(ifname, agg_ifname, rx_sock, readonly_access(rev_vlan_map, ifname).size() + readonly_access(rev_portchan_map, ifname).size(),
                                        (const int *)monitored_msgs, monitored_msg_sz) ?
           DHCP_MON_STATUS_HEALTHY : DHCP_MON_STATUS_UNHEALTHY;
}

static dhcp_mon_status_t dhcp_device_check_agg_multiple_tx(const std::string &ifname)
{
    std::string agg_ifname = agg_dev_prefix + ifname;
    return check_counters_delta_expected(ifname, agg_ifname, tx_sock, readonly_access(rev_vlan_map, ifname).size() + readonly_access(rev_portchan_map, ifname).size(),
                                        (const int *)monitored_msgs, monitored_msg_sz) ?
           DHCP_MON_STATUS_HEALTHY : DHCP_MON_STATUS_UNHEALTHY;
}

static dhcp_mon_status_t dhcp_device_check_agg_multiple_rx_v6(const std::string &ifname)
{
    std::string agg_ifname = agg_dev_prefix + ifname;
    return check_counters_delta_expected(ifname, agg_ifname, rx_sock_v6, readonly_access(rev_vlan_map, ifname).size() + readonly_access(rev_portchan_map, ifname).size(),
                                        (const int *)monitored_v6_msgs, monitored_v6_msg_sz) ?
           DHCP_MON_STATUS_HEALTHY : DHCP_MON_STATUS_UNHEALTHY;
}

static dhcp_mon_status_t dhcp_device_check_agg_multiple_tx_v6(const std::string &ifname)
{
    std::string agg_ifname = agg_dev_prefix + ifname;
    return check_counters_delta_expected(ifname, agg_ifname, tx_sock_v6, readonly_access(rev_vlan_map, ifname).size() + readonly_access(rev_portchan_map, ifname).size(),
                                        (const int *)monitored_v6_msgs, monitored_v6_msg_sz) ?
           DHCP_MON_STATUS_HEALTHY : DHCP_MON_STATUS_UNHEALTHY;
}

/**
 * @code dhcp_print_counters(ifname, type, rx_counter, tx_counter);
 *
 * @brief prints status counters to syslog.
 *
 * @param ifname           interface name
 * @param type             counter type
 * @param rx_counter       rx counter
 * @param tx_counter       tx counter
 *
 * @return none
 */
static void dhcp_print_counters(const std::string &ifname, dhcp_counters_type_t type, const counter_t &rx_counter, const counter_t &tx_counter)
{
    syslog(
        LOG_INFO,
        "[%*s -%*s rx/tx] Discover: %*" PRIu64 "/%*" PRIu64 ", Offer: %*" PRIu64 "/%*" PRIu64 
        ", Request: %*" PRIu64 "/%*" PRIu64 ", ACK: %*" PRIu64 "/%*" PRIu64,
        IF_NAMESIZE, ifname.c_str(), 13, counter_desc[type],
        DHCP_COUNTER_WIDTH, rx_counter.at(DHCP_MESSAGE_TYPE_DISCOVER),
        DHCP_COUNTER_WIDTH, tx_counter.at(DHCP_MESSAGE_TYPE_DISCOVER),
        DHCP_COUNTER_WIDTH, rx_counter.at(DHCP_MESSAGE_TYPE_OFFER),
        DHCP_COUNTER_WIDTH, tx_counter.at(DHCP_MESSAGE_TYPE_OFFER),
        DHCP_COUNTER_WIDTH, rx_counter.at(DHCP_MESSAGE_TYPE_REQUEST),
        DHCP_COUNTER_WIDTH, tx_counter.at(DHCP_MESSAGE_TYPE_REQUEST),
        DHCP_COUNTER_WIDTH, rx_counter.at(DHCP_MESSAGE_TYPE_ACK),
        DHCP_COUNTER_WIDTH, tx_counter.at(DHCP_MESSAGE_TYPE_ACK)
    );
}

void dhcp_device_print_status(const std::string &ifname, dhcp_counters_type_t type)
{
    switch (type) {
        case DHCP_COUNTERS_CURRENT:
            dhcp_print_counters(ifname, type, sock_mgr_get_sock_info(rx_sock).all_counters[ifname], sock_mgr_get_sock_info(tx_sock).all_counters[ifname]);
            break;
        case DHCP_COUNTERS_SNAPSHOT:
            dhcp_print_counters(ifname, type, sock_mgr_get_sock_info(rx_sock).all_counters_snapshot[ifname], sock_mgr_get_sock_info(tx_sock).all_counters_snapshot[ifname]);
            break;
        case DHCP_COUNTERS_CURRENT_V6:
            dhcp_print_counters(ifname, type, sock_mgr_get_sock_info(rx_sock_v6).all_counters[ifname], sock_mgr_get_sock_info(tx_sock_v6).all_counters[ifname]);
            break;
        case DHCP_COUNTERS_SNAPSHOT_V6:
            dhcp_print_counters(ifname, type, sock_mgr_get_sock_info(rx_sock_v6).all_counters_snapshot[ifname], sock_mgr_get_sock_info(tx_sock_v6).all_counters_snapshot[ifname]);
            break;
        default:
            syslog(LOG_WARNING, "Unsupported counter type %d for interface %s", type, ifname.c_str());
    }
}

void dhcp_device_print_status_debug(const std::string &ifname, dhcp_counters_type_t type)
{
    if (debug_on) {
        dhcp_device_print_status(ifname, type);
    }
}

dhcp_mon_status_t dhcp_device_get_status(const std::string &ifname, dhcp_mon_check_t check_type)
{
    if (sock_mgr_counters_unchanged(ifname, (const int *)monitored_msgs, monitored_msg_sz, (const int *)monitored_v6_msgs, monitored_v6_msg_sz)) {
        return DHCP_MON_STATUS_INDETERMINATE;
    }

    switch (check_type) {
        case DHCP_MON_CHECK_NEGATIVE:
            return dhcp_device_check_negative_health(ifname);
        case DHCP_MON_CHECK_POSITIVE:
            return dhcp_device_check_positive_health(ifname);
        case DHCP_MON_CHECK_POSITIVE_V6:
            return dhcp_device_check_positive_health_v6(ifname);
        case DHCP_MON_CHECK_NEGATIVE_V6:
            return dhcp_device_check_negative_health_v6(ifname);
        case DHCP_MON_CHECK_AGG_EQUAL_RX:
            return dhcp_device_check_agg_equal_rx(ifname);
        case DHCP_MON_CHECK_AGG_EQUAL_TX:
            return dhcp_device_check_agg_equal_tx(ifname);
        case DHCP_MON_CHECK_AGG_EQUAL_RX_V6:
            return dhcp_device_check_agg_equal_rx_v6(ifname);
        case DHCP_MON_CHECK_AGG_EQUAL_TX_V6:
            return dhcp_device_check_agg_equal_tx_v6(ifname);
        case DHCP_MON_CHECK_AGG_MULTIPLE_RX:
            return dhcp_device_check_agg_multiple_rx(ifname);
        case DHCP_MON_CHECK_AGG_MULTIPLE_TX:
            return dhcp_device_check_agg_multiple_tx(ifname);
        case DHCP_MON_CHECK_AGG_MULTIPLE_RX_V6:
            return dhcp_device_check_agg_multiple_rx_v6(ifname);
        case DHCP_MON_CHECK_AGG_MULTIPLE_TX_V6:
            return dhcp_device_check_agg_multiple_tx_v6(ifname);
        default:
            break;
    }

    return DHCP_MON_STATUS_UNHEALTHY;
}

int initialize_intf_mac_and_ip_addr(dhcp_device_context_t *context)
{
    int rv = -1;

    do {
        // Get mac
        int fd;
        struct ifreq ifr;

        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            syslog(LOG_ALERT, "socket: %s", strerror(errno));
            break;
        }
        strncpy(ifr.ifr_name, context->intf, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            syslog(LOG_ALERT, "ioctl: %s", explain_ioctl(fd, SIOCGIFHWADDR, &ifr));
            close(fd);
            break;
        }
        memcpy(context->mac, ifr.ifr_hwaddr.sa_data, sizeof(context->mac));
        syslog(LOG_INFO, "Interface %s has MAC %s", context->intf,
               generate_addr_string(context->mac, ETHER_ADDR_LEN).c_str());
        close(fd);

        // Get ip address
        struct ifaddrs *ifaddr;
        int num_ip_addr = 0, num_ipv6_gua = 0, num_ipv6_lla = 0;
        
        if (getifaddrs(&ifaddr) < 0) {
            syslog(LOG_ALERT, "getifaddrs: %s", strerror(errno));
            break;
        }
        for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || strcmp(ifa->ifa_name, context->intf) != 0)
                continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *ip = (struct sockaddr_in *)ifa->ifa_addr;
                if (!addr_is_primary(context->intf, &ip->sin_addr)) {
                    syslog(LOG_INFO, "Interface %s has non-primary IPv4 address %s, skipping",
                           context->intf,
                           generate_addr_string((uint8_t *)&ip->sin_addr, sizeof(ip->sin_addr)).c_str());
                    continue;
                }
                context->ip = ip->sin_addr;
                syslog(LOG_INFO, "Interface %s has IPv4 address %s", context->intf,
                       generate_addr_string((uint8_t *)&context->ip, sizeof(context->ip)).c_str());
                num_ip_addr++;
                continue;
            }
            if (ifa->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                if (IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr)) {
                    context->ipv6_lla = ipv6->sin6_addr;
                    syslog(LOG_INFO, "Interface %s has IPv6 LLA %s", context->intf,
                           generate_addr_string((uint8_t *)&context->ipv6_lla, sizeof(context->ipv6_lla)).c_str());
                    num_ipv6_lla++;
                } else {
                    context->ipv6_gua = ipv6->sin6_addr;
                    syslog(LOG_INFO, "Interface %s has IPv6 GUA %s", context->intf,
                           generate_addr_string((uint8_t *)&context->ipv6_gua, sizeof(context->ipv6_gua)).c_str());
                    num_ipv6_gua++;
                }
                continue;
            }
        }
        freeifaddrs(ifaddr);

        if (num_ip_addr != 1 || (num_ipv6_gua != 1 && num_ipv6_lla != 1)) {
            syslog(LOG_ALERT, "Unable to find exactly 1 ip addr, 1 ipv6 GUA and 1 ipv6 LLA on physical interface "
                   "and 1 ipv6 loopback addr on loopback interface: %s", context->intf);
            break;
        }

        rv = 0;
    } while (0);

    return rv;
}

void dhcp_device_get_ip(const dhcp_device_context_t *context, in_addr *ip, in6_addr *ipv6_gua, in6_addr *ipv6_lla)
{
    if (ip != NULL) {
        *ip = context->ip;
    }
    if (ipv6_gua != NULL) {
        *ipv6_gua = context->ipv6_gua;
    }
    if (ipv6_lla != NULL) {
        *ipv6_lla = context->ipv6_lla;
    }
}

dhcp_device_context_t* dhcp_device_init(const char *ifname, char intf_type)
{
    dhcp_device_context_t *context = NULL;

    do {
        syslog(LOG_INFO, "Initializing context interface %s", ifname);
        
        // allocate memory for device context
        context = (dhcp_device_context_t *)malloc(sizeof(dhcp_device_context_t));
        if (context == NULL) {
            syslog(LOG_ALERT, "malloc: failed to allocated device context memory for '%s'", ifname);
            break;
        }

        // set device name
        strncpy(context->intf, ifname, sizeof(context->intf) - 1);
        context->intf[sizeof(context->intf) - 1] = '\0';
        
        // set device meta data
        if (initialize_intf_mac_and_ip_addr(context) < 0) {
            syslog(LOG_ALERT, "Failed to initialize mac/ip address for interface %s", ifname);
            free(context);
            context = NULL;
            break;
        }
        
        context->is_uplink = intf_type == 'u';
        context->is_downlink = intf_type == 'd';
        syslog(LOG_INFO, "Interface %s is %s", ifname,
               context->is_uplink ? "uplink (north)" : (context->is_downlink ? "downlink (south)" : "management"));

        syslog(LOG_INFO, "Successfully initialized context interface %s", ifname);
    } while (0);

    return context;
}

void dhcp_device_free(dhcp_device_context_t *context)
{
    free(context);
}