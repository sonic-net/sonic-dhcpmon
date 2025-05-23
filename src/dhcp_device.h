/**
 * @file dhcp_device.h
 *
 *  device (interface) module
 */

#ifndef DHCP_DEVICE_H_
#define DHCP_DEVICE_H_

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/thread.h>

#include "subscriberstatetable.h"
#include "util.h"

extern std::shared_ptr<swss::DBConnector> mCountersDbPtr;
extern std::shared_ptr<swss::DBConnector> mStateDbPtr;
extern bool dual_tor_sock;
extern std::unordered_map<std::string, struct intf*> intfs;

/**
 * DHCP message types
 **/
typedef enum
{
    DHCP_MESSAGE_TYPE_DISCOVER = 1,
    DHCP_MESSAGE_TYPE_OFFER    = 2,
    DHCP_MESSAGE_TYPE_REQUEST  = 3,
    DHCP_MESSAGE_TYPE_DECLINE  = 4,
    DHCP_MESSAGE_TYPE_ACK      = 5,
    DHCP_MESSAGE_TYPE_NAK      = 6,
    DHCP_MESSAGE_TYPE_RELEASE  = 7,
    DHCP_MESSAGE_TYPE_INFORM   = 8,
    BOOTP_MESSAGE              = 9,

    DHCP_MESSAGE_TYPE_COUNT
} dhcp_message_type_t;

enum
{
    OPTION_DHCP_MESSAGE_TYPE = 53,
};

/** counters type */
typedef enum
{
    DHCP_COUNTERS_CURRENT,      /** DHCP current counters */
    DHCP_COUNTERS_SNAPSHOT,     /** DHCP snapshot counters */

    DHCP_COUNTERS_COUNT
} dhcp_counters_type_t;

/** dhcp health status */
typedef enum
{
    DHCP_MON_STATUS_HEALTHY,        /** DHCP relay is healthy */
    DHCP_MON_STATUS_UNHEALTHY,      /** DHCP relay is unhealthy and is missing out on some packets */
    DHCP_MON_STATUS_INDETERMINATE,  /** DHCP relay health could not be determined */
} dhcp_mon_status_t;

/** dhcp check type */
typedef enum
{
    DHCP_MON_CHECK_NEGATIVE,    /** Presence of relayed DHCP packets activity is flagged as unhealthy state */
    DHCP_MON_CHECK_POSITIVE,    /** Validate that received DORA packets are relayed */
} dhcp_mon_check_t;

typedef enum
{
    DHCP_VALID,
    DHCP_INVALID,
    DHCP_UNKNOWN
} dhcp_mon_packet_valid_type_t;

/** DHCP device (interface) context */
typedef struct
{
    int rx_sock;                    /** Raw socket associated with this device/interface to count rx packets */
    int tx_sock;                    /** Raw socket associated with this device/interface to count tx packets*/
    in_addr_t ip;                   /** network address of this device (interface) */
    uint8_t mac[ETHER_ADDR_LEN];    /** hardware address of this device (interface) */
    in_addr_t giaddr_ip;            /** Gateway IP address */
    uint8_t is_uplink;              /** north interface? */
    char intf[IF_NAMESIZE];         /** device (interface) name */
    size_t snaplen;                 /** snap length or buffer size */
    uint64_t counters[DHCP_COUNTERS_COUNT][DHCP_DIR_COUNT][DHCP_MESSAGE_TYPE_COUNT];
                                    /** current/snapshot counters of DHCP packets */
} dhcp_device_context_t;

extern std::string db_counter_name[DHCP_MESSAGE_TYPE_COUNT];

/**
 * @code initialize_intf_mac_and_ip_addr(context);
 *
 * @brief initializes device (interface) mac/ip addresses
 *
 * @param context           pointer to device (interface) context
 *
 * @return 0 on success, otherwise for failure
 */
int initialize_intf_mac_and_ip_addr(dhcp_device_context_t *context);

/**
 * @code dhcp_device_get_ip(context, ip);
 *
 * @brief Accessor method
 *
 * @param context       pointer to device (interface) context
 * @param ip(out)       pointer to device IP
 *
 * @return 0 on success, otherwise for failure
 */
int dhcp_device_get_ip(dhcp_device_context_t *context, in_addr_t *ip);

/**
 * @code dhcp_device_get_aggregate_context();
 *
 * @brief Accessor method
 *
 * @return pointer to aggregate device (interface) context
 */
dhcp_device_context_t* dhcp_device_get_aggregate_context();

/**
 * @code dhcp_device_get_counter(dhcp_packet_direction_t dir);
 * @brief Accessor method
 * @return pointer to counter
 */
std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>>* dhcp_device_get_counter(dhcp_packet_direction_t dir);

/**
 * @code dhcp_device_init(context, intf, is_uplink);
 *
 * @brief initializes device (interface) that handles packet capture per interface.
 *
 * @param context(inout)    pointer to device (interface) context
 * @param intf              interface name
 * @param is_uplink         uplink interface
 *
 * @return 0 on success, otherwise for failure
 */
int dhcp_device_init(dhcp_device_context_t **context,
                     const char *intf,
                     uint8_t is_uplink);

/**
 * @code int dhcp_device_start_capture(size_t snaplen, struct event_mgr *rx_event_mgr, struct event_mgr *tx_event_mgr, in_addr_t giaddr_ip);
 *
 * @brief starts packet capture on this interface
 *
 * @param snaplen           length of packet capture
 * @param rx_event_mgr      evnet mgr for rx event
 * @param tx_event_mgr      event mgr for for tx event
 * @param giaddr_ip         gateway IP address
 *
 * @return 0 on success, otherwise for failure
 */
int dhcp_device_start_capture(size_t snaplen, struct event_mgr *rx_event_mgr, struct event_mgr *tx_event_mgr, in_addr_t giaddr_ip);

/**
 * @code dhcp_device_shutdown(context);
 *
 * @brief shuts down device (interface). Also, stops packet capture on interface and cleans up any allocated memory
 *
 * @param context   Device (interface) context
 *
 * @return nonedhcp_device_shutdown
 */
void dhcp_device_shutdown(dhcp_device_context_t *context);

/**
 * @code dhcp_device_get_status(check_type, context);
 *
 * @brief collects DHCP relay status info for a given interface. If context is null, it will report aggregate
 *        status
 *
 * @param check_type        Type of validation
 * @param context           Device (interface) context
 *
 * @return DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
dhcp_mon_status_t dhcp_device_get_status(dhcp_mon_check_t check_type, dhcp_device_context_t *context);

/**
 * @code dhcp_device_update_snapshot(context);
 *
 * @param context   Device (interface) context
 *
 * @brief Update device/interface counters snapshot
 */
void dhcp_device_update_snapshot(dhcp_device_context_t *context);

/**
 * @code dhcp_device_print_status(context, type);
 *
 * @brief prints status counters to syslog. If context is null, it will print aggregate status
 *
 * @param context       Device (interface) context
 * @param counters_type Counter type to be printed
 *
 * @return none
 */
void dhcp_device_print_status(dhcp_device_context_t *context, dhcp_counters_type_t type);

/**
 * @code                void initialize_db_counter(std::string &ifname)
 * @brief               Initialize the counter in counters_db with interface name
 * @param ifname        interface name
 * @return              none
 */
void initialize_db_counters(std::string &ifname);

/**
 * @code initialize_cache_counter(std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>> &counters, std::string interface_name);
 * @brief Initialize cache counter per interface
 * @param counters         counter data
 * @param interface_name   string value of interface name
 */
void initialize_cache_counter(std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>> &counters, std::string interface_name);

/**
 * @code                void increase_cache_counter(std::string &ifname, uint8_t type, dhcp_packet_direction_t dir)
 * @brief               Increase cache counter
 * @param ifname        Interface name
 * @param type          Packet type
 * @param dir           Packet direction
 * @return              none
 */
void increase_cache_counter(std::string &ifname, uint8_t type, dhcp_packet_direction_t dir);

/**
 * @code                std::string generate_json_string(const std::unordered_map<uint8_t, uint64_t>* counter)
 * @brief               Generate JSON string by counter dict
 * @param counter       Counter dict
 * @return              none
 */
std::string generate_json_string(const std::unordered_map<uint8_t, uint64_t>* counter);

#endif /* DHCP_DEVICE_H_ */
