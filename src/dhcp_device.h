/**
 * @file dhcp_device.h
 *
 * device (interface) module
 * 
 * Collection of functions to manage context interface information, it's creation, deletion, and various checks on an interface.
 * Context interface is the interface input directly from command line. However operations on specific context interface has been
 * extended to physical interfaces under the context interface, as well as aggregate interfaces. Thus we don't use context interface
 * directly in many places, instead we use interface name string to identify an interface. In case we need context interface info, we
 * will query device manager to get the context interface from interface name.
 */

#ifndef DHCP_DEVICE_H_
#define DHCP_DEVICE_H_

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <string>

/** DHCP message types */
typedef enum
{
    DHCP_MESSAGE_TYPE_UNKNOWN,
    DHCP_MESSAGE_TYPE_DISCOVER,
    DHCP_MESSAGE_TYPE_OFFER,
    DHCP_MESSAGE_TYPE_REQUEST,
    DHCP_MESSAGE_TYPE_DECLINE,
    DHCP_MESSAGE_TYPE_ACK,
    DHCP_MESSAGE_TYPE_NAK,
    DHCP_MESSAGE_TYPE_RELEASE,
    DHCP_MESSAGE_TYPE_INFORM, // last of standard types
    DHCP_MESSAGE_TYPE_BOOTP,
    DHCP_MESSAGE_TYPE_MALFORMED,
    DHCP_MESSAGE_TYPE_IGNORED,
    DHCP_MESSAGE_TYPE_COUNT
} dhcp_message_type_t;

/* db counter name array, message type range [1, 9] */
extern const std::string db_counter_name[DHCP_MESSAGE_TYPE_COUNT];

/**
 * @code get_dhcp_message_type_desc(t);
 * @brief get string description of dhcp_message_type_t
 * @param t     dhcp_message_type_t
 * @return      string description
 */
inline const char* get_dhcp_message_type_desc(dhcp_message_type_t t) {
    switch (t) {
        case DHCP_MESSAGE_TYPE_DISCOVER: return "DHCP_MESSAGE_TYPE_DISCOVER";
        case DHCP_MESSAGE_TYPE_OFFER: return "DHCP_MESSAGE_TYPE_OFFER";
        case DHCP_MESSAGE_TYPE_REQUEST: return "DHCP_MESSAGE_TYPE_REQUEST";
        case DHCP_MESSAGE_TYPE_DECLINE: return "DHCP_MESSAGE_TYPE_DECLINE";
        case DHCP_MESSAGE_TYPE_ACK: return "DHCP_MESSAGE_TYPE_ACK";
        case DHCP_MESSAGE_TYPE_NAK: return "DHCP_MESSAGE_TYPE_NAK";
        case DHCP_MESSAGE_TYPE_RELEASE: return "DHCP_MESSAGE_TYPE_RELEASE";
        case DHCP_MESSAGE_TYPE_INFORM: return "DHCP_MESSAGE_TYPE_INFORM";
        case DHCP_MESSAGE_TYPE_BOOTP: return "DHCP_MESSAGE_TYPE_BOOTP";
        default: return "UNKNOWN DHCP_MESSAGE_TYPE";
    }
}

/** DHCPv6 message types */
typedef enum
{
    DHCPV6_MESSAGE_TYPE_UNKNOWN,
    DHCPV6_MESSAGE_TYPE_SOLICIT,
    DHCPV6_MESSAGE_TYPE_ADVERTISE,
    DHCPV6_MESSAGE_TYPE_REQUEST,
    DHCPV6_MESSAGE_TYPE_CONFIRM,
    DHCPV6_MESSAGE_TYPE_RENEW,
    DHCPV6_MESSAGE_TYPE_REBIND,
    DHCPV6_MESSAGE_TYPE_REPLY,
    DHCPV6_MESSAGE_TYPE_RELEASE,
    DHCPV6_MESSAGE_TYPE_DECLINE,
    DHCPV6_MESSAGE_TYPE_RECONFIGURE,
    DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST,
    DHCPV6_MESSAGE_TYPE_RELAY_FORW,
    DHCPV6_MESSAGE_TYPE_RELAY_REPL, // last of standard types
    DHCPV6_MESSAGE_TYPE_MALFORMED,
    DHCPV6_MESSAGE_TYPE_IGNORED,
    DHCPV6_MESSAGE_TYPE_COUNT
} dhcpv6_message_type_t;

/* db counter name array, message type range [1, 13] */
extern const std::string db_counter_name_v6[DHCPV6_MESSAGE_TYPE_COUNT];

/**
 * @code get_dhcpv6_message_type_desc(t);
 * @brief get string description of dhcpv6_message_type_t
 * @param t     dhcpv6_message_type_t
 * @return      string description
 */
inline const char* get_dhcpv6_message_type_desc(dhcpv6_message_type_t t) {
    switch (t) {
        case DHCPV6_MESSAGE_TYPE_SOLICIT: return "DHCPV6_MESSAGE_TYPE_SOLICIT";
        case DHCPV6_MESSAGE_TYPE_ADVERTISE: return "DHCPV6_MESSAGE_TYPE_ADVERTISE";
        case DHCPV6_MESSAGE_TYPE_REQUEST: return "DHCPV6_MESSAGE_TYPE_REQUEST";
        case DHCPV6_MESSAGE_TYPE_CONFIRM: return "DHCPV6_MESSAGE_TYPE_CONFIRM";
        case DHCPV6_MESSAGE_TYPE_RENEW: return "DHCPV6_MESSAGE_TYPE_RENEW";
        case DHCPV6_MESSAGE_TYPE_REBIND: return "DHCPV6_MESSAGE_TYPE_REBIND";
        case DHCPV6_MESSAGE_TYPE_REPLY: return "DHCPV6_MESSAGE_TYPE_REPLY";
        case DHCPV6_MESSAGE_TYPE_RELEASE: return "DHCPV6_MESSAGE_TYPE_RELEASE";
        case DHCPV6_MESSAGE_TYPE_DECLINE: return "DHCPV6_MESSAGE_TYPE_DECLINE";
        case DHCPV6_MESSAGE_TYPE_RECONFIGURE: return "DHCPV6_MESSAGE_TYPE_RECONFIGURE";
        case DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST: return "DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST";
        case DHCPV6_MESSAGE_TYPE_RELAY_FORW: return "DHCPV6_MESSAGE_TYPE_RELAY_FORW";
        case DHCPV6_MESSAGE_TYPE_RELAY_REPL: return "DHCPV6_MESSAGE_TYPE_RELAY_REPL";
        default: return "UNKNOWN DHCPV6_MESSAGE_TYPE";
    }
}

/** dhcp health status */
typedef enum
{
    DHCP_MON_STATUS_HEALTHY,        /** DHCP relay is healthy */
    DHCP_MON_STATUS_UNHEALTHY,      /** DHCP relay is unhealthy and is missing out on some packets */
    DHCP_MON_STATUS_INDETERMINATE,  /** DHCP relay health could not be determined */
} dhcp_mon_status_t;

/** counters type */
typedef enum
{
    DHCP_COUNTERS_CURRENT,
    DHCP_COUNTERS_SNAPSHOT,
    DHCP_COUNTERS_CURRENT_V6,
    DHCP_COUNTERS_SNAPSHOT_V6,
    DHCP_COUNTERS_COUNT
} dhcp_counters_type_t;

/** dhcp check type */
typedef enum
{
    DHCP_DEVICE_CHECK_NEGATIVE,            /** Presence of relayed DHCP packets activity is flagged as unhealthy state */
    DHCP_DEVICE_CHECK_POSITIVE,            /** Validate that received DORA packets are relayed */
    DHCP_DEVICE_CHECK_NEGATIVE_V6,         /** Presence of relayed DHCPv6 packets activity is flagged as unhealthy state */
    DHCP_DEVICE_CHECK_POSITIVE_V6,         /** Validate that received SARR packets are relayed */
    DHCP_DEVICE_CHECK_AGG_EQUAL_RX,        /** Validate that aggregate device rx counters equal sum of member interfaces rx counters */
    DHCP_DEVICE_CHECK_AGG_EQUAL_TX,        /** Validate that aggregate device tx counters equal sum of member interfaces tx counters */
    DHCP_DEVICE_CHECK_AGG_EQUAL_RX_V6,     /** Validate that aggregate device rx counters equal sum of member interfaces rx counters for IPv6 */
    DHCP_DEVICE_CHECK_AGG_EQUAL_TX_V6,     /** Validate that aggregate device tx counters equal sum of member interfaces tx counters for IPv6 */
    DHCP_DEVICE_CHECK_AGG_MULTIPLE_RX,     /** Validate that aggregate device rx counters are multiple of member interfaces rx counters */
    DHCP_DEVICE_CHECK_AGG_MULTIPLE_TX,     /** Validate that aggregate device tx counters are multiple of member interfaces tx counters */
    DHCP_DEVICE_CHECK_AGG_MULTIPLE_RX_V6,  /** Validate that aggregate device rx counters are multiple of member interfaces rx counters for IPv6 */
    DHCP_DEVICE_CHECK_AGG_MULTIPLE_TX_V6   /** Validate that aggregate device tx counters are multiple of member interfaces tx counters for IPv6 */
} dhcp_device_check_t;

/** Monitored DHCP message type */
extern const dhcp_message_type_t monitored_msgs[];

/** Number of monitored DHCP message type */
extern uint8_t monitored_msg_sz;

/** Monitored DHCPv6 message type */
extern const dhcpv6_message_type_t monitored_v6_msgs[];

/** Number of monitored DHCPv6 message type */
extern uint8_t monitored_v6_msg_sz;

/** Device (interface) types */
typedef enum
{
    DHCP_DEVICE_INTF_TYPE_UPLINK,
    DHCP_DEVICE_INTF_TYPE_DOWNLINK,
    DHCP_DEVICE_INTF_TYPE_MGMT,
    DHCP_DEVICE_INTF_TYPE_COUNT
} dhcp_device_intf_t;

/** Interface type name array */
extern const char *intf_type_name[DHCP_DEVICE_INTF_TYPE_COUNT];

/** DHCP device (interface) context */
typedef struct
{
    uint8_t mac[ETHER_ADDR_LEN];        /** hardware address of this device (interface) */
    dhcp_device_intf_t intf_type;       /** interface type: uplink, downlink, or mgmt */
    char intf[IF_NAMESIZE];             /** device (interface) name */
    struct in_addr ip;                  /** network address of this device (interface) */
    struct in6_addr ipv6_gua;           /** network address of this device (interface) */
    struct in6_addr ipv6_lla;           /** link local address of this device (interface) */
} dhcp_device_context_t;

/**
 * @code initialize_intf_mac_and_ip_addr(context);
 *
 * @brief initializes device (interface) mac/ip addresses
 *
 * @param context           pointer to device (interface) context
 *
 * @return 0 on success, negative for failure
 */
int initialize_intf_mac_and_ip_addr(dhcp_device_context_t *context);

/**
 * @code dhcp_device_get_ip(context, ip);
 *
 * @brief Accessor method, retrieves device (interface) IP address from context and store it in ip if ip is not NULL
 *
 * @param context       pointer to device (interface) context
 * @param ip(out)       pointer to device IP
 * @param ipv6_gua(out) pointer to device IPv6 GUA
 * @param ipv6_lla(out) pointer to device IPv6 LLA
 *
 * @return none
 */
void dhcp_device_get_ip(const dhcp_device_context_t *context, in_addr *ip, in6_addr *ipv6_gua, in6_addr *ipv6_lla);

/**
 * @code dhcp_device_init(ifname, is_uplink);
 *
 * @brief initializes device (interface) that handles packet capture per interface.
 *
 * @param ifname        interface name
 * @param intf_type     'u' for uplink (north) interface, 'd' for downlink (south) interface, 'm' for mgmt interface
 *
 * @return pointer to device (interface) context on success, NULL otherwise
 */
dhcp_device_context_t* dhcp_device_init(const char *ifname, char intf_type);

/**
 * @code dhcp_device_free(context);
 *
 * @brief frees device (interface) context
 *
 * @param context       pointer to device (interface) context
 *
 * @return none
 */
void dhcp_device_free(dhcp_device_context_t *context);

/**
 * @code dhcp_device_get_status(ifname, check_type);
 *
 * @brief collects DHCPv4/v6 relay status info for a given interface. The interface name can be context interface name,
 *        physical interface name under context interface, or aggregate interface name.
 *
 * @param ifname            Interface name
 * @param check_type        Type of validation
 *
 * @return DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
dhcp_mon_status_t dhcp_device_get_status(const std::string &ifname, dhcp_device_check_t check_type);

/**
 * @code dhcp_device_print_status(ifname, type);
 *
 * @brief prints status counters to syslog.
 *
 * @param ifname           interface name
 * @param type             counter type
 *
 * @return none
 */
void dhcp_device_print_status(const std::string &ifname, dhcp_counters_type_t type);

/**
 * @code dhcp_device_print_status_debug(ifname, type);
 *
 * @brief prints status counters to syslog when debug_on is true.
 *
 * @param ifname           interface name
 * @param type              counter type
 *
 * @return none
 */
void dhcp_device_print_status_debug(const std::string &ifname, dhcp_counters_type_t type);

#endif /* DHCP_DEVICE_H_ */
