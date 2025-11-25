/**
 * @file dhcp_check_profile.h
 * 
 * For each different dhcp/v6 message, we will have different check profile to validate the packet. We expect different things
 * from different topology and message type. Include this header to use the dhcp/v6_msg_check_type_t enum and different profile.
 */

#ifndef DHCPV6_CHECK_PROFILE_H_
#define DHCPV6_CHECK_PROFILE_H_

#include <unordered_map>

#include "dhcp_device.h"

/**
 * DHCP msg check type
 **/
typedef enum
{
    DHCP_CHECK_INTF_TYPE,                      // check packet interface type (uplink/downlink/mgmt)
    DHCP_CHECK_SRC_IP,                         // check source ip address
    DHCP_CHECK_DST_IP,                         // check destination ip address
    DHCP_CHECK_GIADDR,                         // check giaddr address
    DHCP_CHECK_TYPE_COUNT                      // number of check types
} dhcp_msg_check_type_t;

/**
 * DHCPv6 msg check type
 **/
typedef enum
{
    DHCPV6_CHECK_INTF_TYPE,                      // check packet interface type (uplink/downlink/mgmt)
    DHCPV6_CHECK_SRC_IP,                         // check source ip address
    DHCPV6_CHECK_DST_IP,                         // check destination ip address
    DHCPV6_CHECK_LINK_ADDR,                      // check link address
    DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY,      // check link address when relay message option is relay (relay option present)
    DHCPV6_CHECK_LINK_ADDR_INNER_MSG_NOT_RELAY,  // check link address when relay message option is not relay (relay option present)
    DHCPV6_CHECK_PEER_ADDR,                      // check peer address
    DHCPV6_CHECK_INTERFACE_ID,                   // check interface ID, it is by itself optional, by default off for single tor and on for dual tor
    DHCPV6_CHECK_HOP_COUNT,                      // check hop count, we don't need arg for this
    DHCPV6_CHECK_HAS_RELAY_OPT,                  // check has relay message option
    DHCPV6_CHECK_TYPE_COUNT                      // number of check types
} dhcpv6_msg_check_type_t;

/**
 * DHCP msg check profile type, each entry corresponds to a dhcp_msg_check_type_t and its arg, cast to void pointer for consistency
 * this is for a single dhcp message type
 */
// This is the preferred style, but compiler isn't supporting it yet
// typedef const void* const dhcp_msg_check_profile_t[DHCP_CHECK_TYPE_COUNT];
// Unfortunately we have to drop the const here because we still want array like access but also want to use unordered_map
// Uninitialized entries will be initialized to NULL when we loop through the all the enum values
typedef std::unordered_map<dhcp_msg_check_type_t, const void*> dhcp_msg_check_profile_t;

/**
 * DHCPv6 msg check profile type, each entry corresponds to a dhcpv6_msg_check_type_t and its arg, cast to void pointer for consistency
 * this is for a single dhcpv6 message type
 */
// typedef const void* const dhcpv6_msg_check_profile_t[DHCPV6_CHECK_TYPE_COUNT];
typedef std::unordered_map<dhcpv6_msg_check_type_t, const void*> dhcpv6_msg_check_profile_t;

/**
 * DHCP check profile type, each entry corresponds to a dhcp message type and its check profile
 * this is for all dhcp message types
 */
// typedef const dhcp_msg_check_profile_t* const dhcp_check_profile_t[DHCP_MESSAGE_TYPE_COUNT];
typedef std::unordered_map<dhcp_message_type_t, dhcp_msg_check_profile_t*> dhcp_check_profile_t;

/**
 * DHCPv6 check profile type, each entry corresponds to a dhcpv6 message type and its check profile
 * this is for all dhcpv6 message types
 */
// typedef const dhcpv6_msg_check_profile_t* const dhcpv6_check_profile_t[DHCPV6_MESSAGE_TYPE_COUNT];
typedef std::unordered_map<dhcpv6_message_type_t, dhcpv6_msg_check_profile_t*> dhcpv6_check_profile_t;

/**
 * @code get_check_type_desc(c);
 * @brief get string description of dhcp_msg_check_type_t
 * @param c     dhcp_msg_check_type_t
 * @return      string description
 */
inline const char* get_check_type_desc(dhcp_msg_check_type_t c) {
    switch (c) {
        case DHCP_CHECK_INTF_TYPE: return "DHCP_CHECK_INTF_TYPE";
        case DHCP_CHECK_SRC_IP: return "DHCP_CHECK_SRC_IP";
        case DHCP_CHECK_DST_IP: return "DHCP_CHECK_DST_IP";
        case DHCP_CHECK_GIADDR: return "DHCP_CHECK_GIADDR";
        case DHCP_CHECK_TYPE_COUNT: return "DHCP_CHECK_TYPE_COUNT";
        default: return "UNKNOWN DHCP_CHECK_TYPE";
    }
}

/**
 * @code get_check_type_desc_v6(c);
 * @brief get string description of dhcpv6_msg_check_type_t
 * @param c     dhcpv6_msg_check_type_t
 * @return      string description
 */
inline const char* get_check_type_desc_v6(dhcpv6_msg_check_type_t c) {
    switch (c) {
        case DHCPV6_CHECK_INTF_TYPE: return "DHCPV6_CHECK_INTF_TYPE";
        case DHCPV6_CHECK_SRC_IP: return "DHCPV6_CHECK_SRC_IP";
        case DHCPV6_CHECK_DST_IP: return "DHCPV6_CHECK_DST_IP";
        case DHCPV6_CHECK_LINK_ADDR: return "DHCPV6_CHECK_LINK_ADDR";
        case DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY: return "DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY";
        case DHCPV6_CHECK_LINK_ADDR_INNER_MSG_NOT_RELAY: return "DHCPV6_CHECK_LINK_ADDR_INNER_MSG_NOT_RELAY";
        case DHCPV6_CHECK_PEER_ADDR: return "DHCPV6_CHECK_PEER_ADDR";
        case DHCPV6_CHECK_INTERFACE_ID: return "DHCPV6_CHECK_INTERFACE_ID";
        case DHCPV6_CHECK_HOP_COUNT: return "DHCPV6_CHECK_HOP_COUNT";
        case DHCPV6_CHECK_HAS_RELAY_OPT: return "DHCPV6_CHECK_HAS_RELAY_OPT";
        case DHCPV6_CHECK_TYPE_COUNT: return "DHCPV6_CHECK_TYPE_COUNT";
        default: return "UNKNOWN DHCPV6_CHECK_TYPE";
    }
}

// dhcp check profile to use
extern dhcp_check_profile_t* dhcp_check_profile_ptr_rx;
extern dhcp_check_profile_t* dhcp_check_profile_ptr_tx;

// dhcpv6 check profile to use
extern dhcpv6_check_profile_t* dhcpv6_check_profile_ptr_rx;
extern dhcpv6_check_profile_t* dhcpv6_check_profile_ptr_tx;

// dhcp check profile for T0 topology
extern dhcp_check_profile_t dhcp_check_profile_t0_relay_rx;
extern dhcp_check_profile_t dhcp_check_profile_t0_relay_tx;

// dhcpv6 check profile for T0/T1 topology
extern dhcpv6_check_profile_t dhcpv6_check_profile_relay_rx;
extern dhcpv6_check_profile_t dhcpv6_check_profile_relay_tx;

#endif /* DHCPV6_CHECK_PROFILE_H_ */