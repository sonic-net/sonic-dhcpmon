/**
 * @file packet_handler.h
 *
 * Handles incoming packets captured by raw socket
 */

#ifndef PACKET_HANDLER_H_
#define PACKET_HANDLER_H_

#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "dhcp_device.h"

/** DHCP header size, excluding the variable option section}*/
#define DHCP_HEADER_SIZE 240

/** Start of Ethernet header of a captured frame */
#define ETHER_START_OFFSET 0
/** Start of IP header of a captured frame */
#define IP_START_OFFSET (ETHER_START_OFFSET + ETHER_HDR_LEN)
/** Start of UDP header of a captured frame */
#define UDP_START_OFFSET (IP_START_OFFSET + sizeof(struct iphdr))
/** Start of DHCP header of a captured frame */
#define DHCP_START_OFFSET (UDP_START_OFFSET + sizeof(struct udphdr))
/** Start of DHCP Options segment of a captured frame */
#define DHCP_OPTIONS_START_OFFSET (DHCP_START_OFFSET + DHCP_HEADER_SIZE)
/** Offset of DHCP GIADDR */
#define DHCP_GIADDR_OFFSET (DHCP_START_OFFSET + 24)
/** Offset of magic cookie */
#define DHCP_MAGIC_COOKIE_OFFSET (DHCP_START_OFFSET + 236)
/** 32-bit decimal of 99.130.83.99 (indicate DHCP packets), Refer to RFC 2131 */
#define DHCP_MAGIC_COOKIE 1669485411
/** The minimum value of DHCP MTU */
#define DHCP_MTU_MIN 576

/** DHCPv6 header size, excluding the variable option section}*/
#define DHCPV6_HEADER_SIZE 4
/** DHCPv6 relay header size, excluding the variable option section */
#define DHCPV6_RELAY_HEADER_SIZE 34
/** The minimum value of DHCPv6 MTU */
#define DHCPV6_MTU_MIN 1280
/** The maximum number of hops for DHCPv6 relay messages */
#define DHCPV6_RELAY_MAX_HOP 8

enum
{
    OPTION_DHCP_MESSAGE_TYPE = 53,
    OPTION_DHCP_MESSAGE_END = 255,
};

enum
{
    OPTION_DHCPV6_RELAY_MSG = 9,
    OPTION_DHCPV6_INTERFACE_ID = 18,
};

#define DHCPV6_OPTION_CODE_MAX 150

typedef void (*packet_handler_t)(const std::string &, const dhcp_device_context_t *, ssize_t);

/* packet handler function for different scenarios */
void rx_packet_handler(const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz);
void tx_packet_handler(const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz);
void rx_packet_handler_v6(const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz);
void tx_packet_handler_v6(const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz);

/**
 * @code callback_common(fd, event, arg);
 *
 * @brief common callback for libevent which is called every time out in order to read queued incoming packet capture
 *
 * @param fd            socket to read from
 * @param event         libevent triggered event
 * @param arg           user provided argument for callback (interface context)
 *
 * @return none
 */
void callback_common(int fd, short event, void *arg);

#endif /* PACKET_HANDLER_H_*/
