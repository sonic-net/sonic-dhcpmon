/**
 * @file packet_handler.cpp
 *
 *  Implementation of packet handler functions
 */

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#include "packet_handler.h"

#include "sock_mgr.h" /** to update to counter */
#include "dhcp_devman.h" /** to get the interface info and context */
#include "util.h"

/**
 * @code _increase_cache_counter(ifname, sock, type);
 * @brief helper function to increase cache counter. Simple increase of counter, no complications. In the event of
 *        extremely unexpected nonexistent ifname, just fail
 * @param ifname       interface name
 * @param sock         socket number
 * @param type         message type
 * @return             none
 */
static inline void _increase_cache_counter(const std::string &ifname, int sock, uint8_t type)
{
    syslog_debug(LOG_INFO, "_increase_cache_counter: increasing cache counter for ifname %s, sock %d, type %d",
                 ifname.c_str(), sock, type);
    sock_mgr_get_sock_info(sock).all_counters.at(ifname)[type]++;
}

/**
 * @code increase_cache_counter(ifname, context, sock, type, dup_to_context);
 * @brief increase cache counter for given ifname, and optionally for context ifname and aggregate device
 *        the type has to be valid, there will be no more checking. Type check before hand.
 * @param ifname            interface name
 * @param context           pointer to device context
 * @param sock              socket number
 * @param type              message type
 * @param dup_to_context    whether to duplicate increase to context interface name
 * @return                  none
 */
static void increase_cache_counter(const std::string &ifname, const dhcp_device_context_t *context, int sock, uint8_t type, bool dup_to_context=false)
{
    _increase_cache_counter(ifname, sock, type);

    if (dup_to_context) {
        _increase_cache_counter(std::string(context->intf), sock, type);
    }

    // we seperate mgmt interface from others and do not increase agg counter
    if (mgmt_ifname != "" && mgmt_ifname.compare(context->intf) == 0) {
        return;
    }

    // when ifname belongs to another context ifname, increase the aggregate counter for that context, 
    // else when ifname is the context, we increase agg counter for all.
    _increase_cache_counter(get_agg_counter_ifname(ifname, context->intf), sock, type);
}

/**
 * @code  check_dhcp_option_53_rx(option_53, context, iphdr, buffer);
 * @brief Check whether the received DHCP packet with given option 53 is valid for counting
 * @param option_53     DHCP option 53 value
 * @param context       pointer to device context
 * @param iphdr         pointer to IP header
 * @param buffer        pointer to the whole packet buffer
 * @return              true if valid, false otherwise
 */
static bool check_dhcp_option_53_rx(uint8_t option_53, const dhcp_device_context_t *context, const struct iphdr *iphdr, const uint8_t *buffer)
{
    bool is_valid = false;

    syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: option_53 %d on interface %s", option_53, context->intf);

    switch (option_53) {
        case DHCP_MESSAGE_TYPE_DISCOVER:
        case DHCP_MESSAGE_TYPE_REQUEST:
        case DHCP_MESSAGE_TYPE_DECLINE:
        case DHCP_MESSAGE_TYPE_RELEASE:
        case DHCP_MESSAGE_TYPE_INFORM: {
            /**
             * For packets from DHCP client to DHCP server, wouldn't count packets which already have other giaddr
             * 
             * RX packets, means received from client. Even if the packets here are all related on downstream Vlan, but TX packets with giaddr not equal
             * to current gateway wouldn't be counted, to avoid incorrect counting, wouldn't count RX packets which already have other giaddr
             * 
             * TODO add support to count packets with giaddr no equal to current gateway
             */
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp message sent by client, context interface %s", context->intf);

            if (context->is_uplink) {
                syslog_debug(LOG_WARNING, "check_dhcp_option_53_rx: uplink rx packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp message on downlink context interface %s", context->intf);
            
            if (iphdr->daddr != INADDR_BROADCAST && iphdr->daddr != giaddr_ip.s_addr) {
                syslog_debug(LOG_WARNING, "check_dhcp_option_53_rx: ip packet dst ip %s not broadcast or gateway ip %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&iphdr->daddr, sizeof(iphdr->daddr)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: ip packet dst ip %s is broadcast or gateway ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&iphdr->daddr, sizeof(iphdr->daddr)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                         context->intf);

            in_addr packet_giaddr_ip = *((in_addr *)(buffer + DHCP_GIADDR_OFFSET));
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp packet giaddr ip %s, gateway giaddr ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&packet_giaddr_ip, sizeof(packet_giaddr_ip)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                         context->intf);

            if (packet_giaddr_ip.s_addr != 0 && packet_giaddr_ip.s_addr != giaddr_ip.s_addr) {
                syslog_debug(LOG_WARNING, "check_dhcp_option_53_rx: dhcp packet giaddr ip %s not 0 or gateway giaddr ip %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&packet_giaddr_ip, sizeof(packet_giaddr_ip)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp packet giaddr ip %s is 0 or gateway giaddr ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&packet_giaddr_ip, sizeof(packet_giaddr_ip)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                         context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp message valid, context interface %s", context->intf);
            break;
        }
        case DHCP_MESSAGE_TYPE_OFFER:
        case DHCP_MESSAGE_TYPE_ACK:
        case DHCP_MESSAGE_TYPE_NAK: {
            /**
            * For packets from DHCP server to DHCP client, would count packets which already have other giaddr
            * 
            * RX packets: means received from server. If dst ip is gateway, means the packets must target to current gateway, no need to check giaddr in dhcphdr
            */
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp message sent by server, context interface %s", context->intf);

            if (context->is_downlink) {
                syslog_debug(LOG_WARNING, "check_dhcp_option_53_rx: downlink rx packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp message on uplink context interface %s", context->intf);

            if (iphdr->daddr != giaddr_ip.s_addr) {
                syslog_debug(LOG_WARNING, "check_dhcp_option_53_rx: ip packet dst ip %s not gateway ip %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&iphdr->daddr, sizeof(iphdr->daddr)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: ip packet dst ip %s is gateway ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&iphdr->daddr, sizeof(iphdr->daddr)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                         context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp message valid, context interface %s", context->intf);
            break;
        }
        default:
            // should not reach here, as option 53 is already validated before
            syslog_debug(LOG_WARNING, "check_dhcp_option_53_rx: unknown dhcp option 53 type %d, context interface %s", option_53, context->intf);
            break;
    }

    syslog_debug(LOG_INFO, "check_dhcp_option_53_rx: dhcp message check result %s on context interface %s", is_valid ? "valid" : "invalid", context->intf);

    return is_valid;
}

/**
 * @code                check_dhcp_option_53_tx(option_53, context, iphdr, buffer);
 * @brief               Check whether the transmitted DHCP packet with given option 53 is valid for counting
 * @param option_53     DHCP option 53 value
 * @param context       pointer to device context
 * @param iphdr         pointer to IP header
 * @param buffer        pointer to the whole packet buffer
 * @return              true if valid, false otherwise
 */
static bool check_dhcp_option_53_tx(uint8_t option_53, const dhcp_device_context_t *context, const struct iphdr *iphdr, const uint8_t *buffer)
{
    bool is_valid = false;

    syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: option_53 %d on context interface %s", option_53, context->intf);

    switch (option_53) {
        case DHCP_MESSAGE_TYPE_DISCOVER:
        case DHCP_MESSAGE_TYPE_REQUEST:
        case DHCP_MESSAGE_TYPE_DECLINE:
        case DHCP_MESSAGE_TYPE_RELEASE:
        case DHCP_MESSAGE_TYPE_INFORM: {
            /**
             * For packets from DHCP client to DHCP server, wouldn't count packets which already have other giaddr
             * 
             * TX packets: means relayed to server. Because one dhcpmon process would capture all packets go through uplink interface, hence
             * we need to compare giaddr to make sure packets are related to current gateway, wouldn'd count packets with giaddr not equal to current gateway
             * 
             * TODO add support to count packets with giaddr no equal to current gateway
             */
            syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp message sent to server, context interface %s", context->intf);

            if (context->is_downlink) {
                syslog_debug(LOG_WARNING, "check_dhcp_option_53_tx: downlink tx packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp message on uplink context interface %s", context->intf);

            in_addr packet_giaddr_ip = *((in_addr *)(buffer + DHCP_GIADDR_OFFSET));
            syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp packet giaddr ip %s, gateway giaddr ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&packet_giaddr_ip, sizeof(packet_giaddr_ip)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                         context->intf);

            if (packet_giaddr_ip.s_addr != giaddr_ip.s_addr) {
                syslog_debug(LOG_WARNING, "check_dhcp_option_53_tx: dhcp packet giaddr ip %s not gateway giaddr ip %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&packet_giaddr_ip, sizeof(packet_giaddr_ip)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp packet giaddr ip %s is gateway giaddr ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&packet_giaddr_ip, sizeof(packet_giaddr_ip)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ip, sizeof(giaddr_ip)).c_str(),
                         context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp message valid, context interface %s", context->intf);
            break;
        }
        case DHCP_MESSAGE_TYPE_OFFER:
        case DHCP_MESSAGE_TYPE_ACK:
        case DHCP_MESSAGE_TYPE_NAK: {
            /**
            * For packets from DHCP server to DHCP client, would count packets which already have other giaddr
            * 
            * TX packets: means relayed to client. The packets caputred here must related to corresponding gateway, hence no need to compare giaddr in dhcphdr
            */
            syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp message sent to client, context interface %s", context->intf);

            if (context->is_uplink) {
                syslog_debug(LOG_WARNING, "check_dhcp_option_53_tx: uplink tx packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp message on downlink context interface %s", context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp message valid, context interface %s", context->intf);
            break;
        }
        default:
            // should not reach here, as option 53 is already validated before
            syslog_debug(LOG_WARNING, "handle_dhcp_option_53_tx: unknown dhcp option 53 type %d, context interface %s", option_53, context->intf);
            break;
    }

    syslog_debug(LOG_INFO, "check_dhcp_option_53_tx: dhcp message check result %s on context interface %s", is_valid ? "valid" : "invalid", context->intf);

    return is_valid;
}

/**
 * @code find_dhcpv6_option(option_code, dhcp6_options, dhcp6_options_sz);
 * @brief find dhcpv6 option in dhcpv6 options buffer
 * @param option_code       dhcpv6 option code to find
 * @param dhcp6_options     pointer to dhcpv6 options buffer
 * @param dhcp6_options_sz  size of dhcpv6 options buffer
 * @return pointer to the option data if found, NULL otherwise
 */
static const uint8_t* find_dhcpv6_option(uint16_t option_code, const uint8_t *dhcp6_options, ssize_t dhcp6_options_sz)
{
    ssize_t offset = 0;
    uint16_t code, len;

    while (offset + 1 < dhcp6_options_sz) {
        code = ntohs(*(uint16_t *)(dhcp6_options + offset));
        len = ntohs(*(uint16_t *)(dhcp6_options + offset + 2));
        if (code == option_code) {
            return dhcp6_options + offset + 4;
        }
        offset += 4 + len;
    }

    return NULL;
}

/**
 * @code check_dhcpv6_message_type_rx(dhcpv6_msg_type, context, ip6hdr, dhcp6hdr, dhcp6_options, dhcp6_options_sz);
 * @brief Check whether the received DHCPv6 packet with given message type is valid for counting
 * @param dhcpv6_msg_type      DHCPv6 message type
 * @param context              pointer to device context
 * @param ip6hdr               pointer to IPv6 header
 * @param dhcp6hdr             pointer to DHCPv6 header
 * @param dhcp6_options        pointer to DHCPv6 options buffer
 * @param dhcp6_options_sz     size of DHCPv6 options buffer
 * @return                     true if valid, false otherwise
 */
static bool check_dhcpv6_message_type_rx(uint8_t dhcpv6_msg_type, const dhcp_device_context_t *context, const struct ip6_hdr *ip6hdr,
                                         const uint8_t *dhcp6hdr, const uint8_t *dhcp6_options, ssize_t dhcp6_options_sz)
{
    bool is_valid = false;

    syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message type %d, context interface %s", dhcpv6_msg_type, context->intf);

    switch (dhcpv6_msg_type) {
        // DHCPv6 messages sent by client, host is server or relay
        case DHCPV6_MESSAGE_TYPE_SOLICIT:
        case DHCPV6_MESSAGE_TYPE_REQUEST:
        case DHCPV6_MESSAGE_TYPE_CONFIRM:
        case DHCPV6_MESSAGE_TYPE_RENEW:
        case DHCPV6_MESSAGE_TYPE_REBIND:
        case DHCPV6_MESSAGE_TYPE_RELEASE:
        case DHCPV6_MESSAGE_TYPE_DECLINE:
        case DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST: {
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message sent by client, host is server or relay, context interface %s", context->intf);

            if (context->is_uplink) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: uplink packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message on downlink context interface %s", context->intf);

            if (find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz) != NULL) {
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 relay inner message found, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 relay inner message not found, context interface %s", context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message valid, context interface %s", context->intf);
            break;
        }
        // DHCPv6 messages sent by server, host is client
        case DHCPV6_MESSAGE_TYPE_ADVERTISE:
        case DHCPV6_MESSAGE_TYPE_REPLY:
        case DHCPV6_MESSAGE_TYPE_RECONFIGURE: {
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message sent by server, host is client, context interface %s", context->intf);

            if (context->is_downlink) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: downlink packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message on uplink context interface %s", context->intf);

            if (find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz) != NULL) {
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 relay inner message found, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 relay inner message not found, context interface %s", context->intf);

            if (memcmp(&ip6hdr->ip6_dst, &giaddr_ipv6, sizeof(in6_addr)) != 0) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: ip6 packet dst ip %s not gateway ip %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&ip6hdr->ip6_dst, sizeof(ip6hdr->ip6_dst)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: ip6 packet dst ip %s is gateway ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&ip6hdr->ip6_dst, sizeof(ip6hdr->ip6_dst)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                         context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message valid, context interface %s", context->intf);
            break;
        }
        // DHCPv6 messages sent by client, host is server or relay
        case DHCPV6_MESSAGE_TYPE_RELAY_FORW: {
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message sent by client, host is server or relay, context interface %s", context->intf);

            if (context->is_uplink) {
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message on uplink context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message on downlink context interface %s", context->intf);

            if (find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz) == NULL) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: dhcpv6 relay message not found, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 relay message found, context interface %s", context->intf);

            if (dhcp6hdr[1] > DHCPV6_RELAY_MAX_HOP) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: dhcpv6 relay hop count %d exceeds max %d, context interface %s, drop",
                             dhcp6hdr[1], DHCPV6_RELAY_MAX_HOP, context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 relay hop count %d within max %d, context interface %s",
                         dhcp6hdr[1], DHCPV6_RELAY_MAX_HOP, context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message valid, context interface %s", context->intf);
            break;
        }
        // DHCPv6 messages sent by server, host is relay
        case DHCPV6_MESSAGE_TYPE_RELAY_REPL: {
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message sent by server, host is relay, context interface %s", context->intf);

            if (context->is_downlink) {
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message on downlink context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message on uplink context interface %s", context->intf);

            if (find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz) == NULL) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: dhcpv6 relay message not found, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 relay message found, context interface %s", context->intf);

            if (memcmp(&ip6hdr->ip6_dst, &giaddr_ipv6, sizeof(in6_addr)) != 0) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: ip6 packet dst ip %s not gateway ip %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&ip6hdr->ip6_dst, sizeof(ip6hdr->ip6_dst)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: ip6 packet dst ip %s is gateway ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&ip6hdr->ip6_dst, sizeof(ip6hdr->ip6_dst)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                         context->intf);

            const uint8_t *option_intf_id = find_dhcpv6_option(OPTION_DHCPV6_INTERFACE_ID, dhcp6_options, dhcp6_options_sz);
            if (option_intf_id == NULL) {
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 interface id option not found, context interface %s", context->intf);
                if (dual_tor_mode && memcmp(dhcp6hdr + 2, &vlan_ipv6_gua, sizeof(in6_addr)) != 0) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: on dual tor, dhcpv6 relay message link address %s is not vlan_ipv6_gua %s, context interface %s, drop",
                                 generate_addr_string(dhcp6hdr + 2, sizeof(in6_addr)).c_str(),
                                 generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(in6_addr)).c_str(),
                                 context->intf);
                    break;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: not on dual tor or dhcpv6 relay message link address %s is vlan_ipv6_gua %s, context interface %s",
                             generate_addr_string(dhcp6hdr + 2, sizeof(in6_addr)).c_str(),
                             generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(in6_addr)).c_str(),
                             context->intf);
            } else {
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 interface id option found, context interface %s", context->intf);
                uint16_t intf_id_len = ntohs(*(uint16_t *)(option_intf_id - 2));
                if (intf_id_len != sizeof(in6_addr)) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: dhcpv6 interface id option length %d is not %d, context interface %s, drop",
                                 intf_id_len, sizeof(in6_addr), context->intf);
                    break;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 interface id option length %d, context interface %s", intf_id_len, context->intf);
                if (memcmp(option_intf_id, &vlan_ipv6_gua, sizeof(in6_addr)) != 0) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: dhcpv6 interface id %s is not vlan_ipv6_gua %s, context interface %s, drop",
                                 generate_addr_string(option_intf_id, sizeof(in6_addr)).c_str(),
                                 generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(in6_addr)).c_str(),
                                 context->intf);
                    break;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 interface id %s is vlan_ipv6_gua %s, context interface %s",
                             generate_addr_string(option_intf_id, sizeof(in6_addr)).c_str(),
                             generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(in6_addr)).c_str(),
                             context->intf);
            }

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message valid, context interface %s", context->intf);
            break;
        }
        default:
            // should not reach here, as option 53 is already validated before
            syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: unknown dhcpv6 message type %d, context interface %s", dhcpv6_msg_type, context->intf);
            break;
    }

    syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 message check result %s on context interface %s", is_valid ? "valid" : "invalid", context->intf);

    return is_valid;
}

/**
 * @code check_dhcpv6_message_type_tx(dhcpv6_msg_type, context, ip6hdr, dhcp6hdr, dhcp6_options, dhcp6_options_sz);
 * @brief Check whether the transmitted DHCPv6 packet with given message type is valid for counting
 * @param dhcpv6_msg_type      DHCPv6 message type
 * @param context              pointer to device context
 * @param ip6hdr               pointer to IPv6 header
 * @param dhcp6hdr             pointer to DHCPv6 header
 * @param dhcp6_options        pointer to DHCPv6 options buffer
 * @param dhcp6_options_sz     size of DHCPv6 options buffer
 * @return                     true if valid, false otherwise
 */
static bool check_dhcpv6_message_type_tx(uint8_t dhcpv6_msg_type, const dhcp_device_context_t *context, const struct ip6_hdr *ip6hdr,
                                         const uint8_t *dhcp6hdr, const uint8_t *dhcp6_options, ssize_t dhcp6_options_sz)
{
    bool is_valid = false;

    switch (dhcpv6_msg_type) {
        // DHCPv6 messages send to server, host is client
        case DHCPV6_MESSAGE_TYPE_SOLICIT:
        case DHCPV6_MESSAGE_TYPE_REQUEST:
        case DHCPV6_MESSAGE_TYPE_CONFIRM:
        case DHCPV6_MESSAGE_TYPE_RENEW:
        case DHCPV6_MESSAGE_TYPE_REBIND:
        case DHCPV6_MESSAGE_TYPE_RELEASE:
        case DHCPV6_MESSAGE_TYPE_DECLINE:
        case DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST: {
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message sent to server, host is client, context interface %s", context->intf);

            if (context->is_downlink) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: uplink tx packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message valid, context interface %s", context->intf);

            if (find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz) != NULL) {
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay inner message found, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay inner message not found, context interface %s", context->intf);

            if (memcmp(&ip6hdr->ip6_src, &giaddr_ipv6, sizeof(in6_addr)) != 0) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: ip6 packet src ip %s not gateway ip %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: ip6 packet src ip %s is gateway ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                         context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message valid, context interface %s", context->intf);
            break;
        }
        // DHCPv6 messages send to client, host is server or relay
        case DHCPV6_MESSAGE_TYPE_ADVERTISE:
        case DHCPV6_MESSAGE_TYPE_REPLY:
        case DHCPV6_MESSAGE_TYPE_RECONFIGURE: {
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message sent to client, host is server or relay, context interface %s", context->intf);

            if (context->is_uplink) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: uplink tx packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message on downlink context interface %s", context->intf);

            if (find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz) != NULL) {
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay inner message found, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay inner message not found, context interface %s", context->intf);

            if (memcmp(&ip6hdr->ip6_src, &vlan_ipv6_gua, sizeof(in6_addr)) != 0 && memcmp(&ip6hdr->ip6_src, &vlan_ipv6_lla, sizeof(in6_addr)) != 0) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: ip6 packet src ip %s not vlan gua %s or lla %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src)).c_str(),
                             generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(vlan_ipv6_gua)).c_str(),
                             generate_addr_string((uint8_t *)&vlan_ipv6_lla, sizeof(vlan_ipv6_lla)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: ip6 packet src ip %s is vlan gua %s or lla %s, context interface %s",
                         generate_addr_string((uint8_t *)&ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src)).c_str(),
                         generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(vlan_ipv6_gua)).c_str(),
                         generate_addr_string((uint8_t *)&vlan_ipv6_lla, sizeof(vlan_ipv6_lla)).c_str(),
                         context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message valid, context interface %s", context->intf);
            break;
        }
        // DHCPv6 messages send to server, host is relay
        case DHCPV6_MESSAGE_TYPE_RELAY_FORW: {
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay forward message sent to server, host is relay, context interface %s", context->intf);

            if (context->is_downlink) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: downlink tx packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message on uplink context interface %s", context->intf);

            const uint8_t *option_relay_msg = find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz);
            if (option_relay_msg == NULL) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: dhcpv6 relay inner message not found, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay inner message found, context interface %s", context->intf);

            if (memcmp(dhcp6hdr + 2, (option_relay_msg[0] < DHCPV6_MESSAGE_TYPE_RELAY_FORW ? &giaddr_ipv6 : &zero_ipv6), sizeof(in6_addr)) != 0) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: dhcpv6 relay message link address %s is not giaddr_ipv6 %s (inner message is not relay) "
                                          "or zero_ipv6 %s (inner message is relay), context interface %s, drop",
                             generate_addr_string(dhcp6hdr + 2, sizeof(in6_addr)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                             generate_addr_string((uint8_t *)&zero_ipv6, sizeof(zero_ipv6)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay message link address %s matches giaddr_ipv6 %s (inner message is not relay) "
                                  "or zero_ipv6 %s (inner message is relay), context interface %s",
                         generate_addr_string(dhcp6hdr + 2, sizeof(in6_addr)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                         generate_addr_string((uint8_t *)&zero_ipv6, sizeof(zero_ipv6)).c_str(),
                         context->intf);

            if (memcmp(&ip6hdr->ip6_src, &giaddr_ipv6, sizeof(in6_addr)) != 0) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: ip6 packet src ip %s not gateway ip %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src)).c_str(),
                             generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: ip6 packet src ip %s is gateway ip %s, context interface %s",
                         generate_addr_string((uint8_t *)&ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src)).c_str(),
                         generate_addr_string((uint8_t *)&giaddr_ipv6, sizeof(giaddr_ipv6)).c_str(),
                         context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message valid, context interface %s", context->intf);
            break;
        }
        // DHCPv6 messages send to relay, host is server or relay
        case DHCPV6_MESSAGE_TYPE_RELAY_REPL: {
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay reply message sent to relay, host is server or relay, context interface %s", context->intf);

            if (context->is_uplink) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: uplink tx packet, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message on downlink context interface %s", context->intf);

            if (find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz) == NULL) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: dhcpv6 relay inner message not found, context interface %s, drop", context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 relay inner message found, context interface %s", context->intf);

            if (memcmp(&ip6hdr->ip6_src, &vlan_ipv6_gua, sizeof(in6_addr)) != 0 && memcmp(&ip6hdr->ip6_src, &vlan_ipv6_lla, sizeof(in6_addr)) != 0) {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_tx: ip6 packet src ip %s not vlan gua %s or lla %s, context interface %s, drop",
                             generate_addr_string((uint8_t *)&ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src)).c_str(),
                             generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(vlan_ipv6_gua)).c_str(),
                             generate_addr_string((uint8_t *)&vlan_ipv6_lla, sizeof(vlan_ipv6_lla)).c_str(),
                             context->intf);
                break;
            }
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: ip6 packet src ip %s is vlan gua %s or lla %s, context interface %s",
                         generate_addr_string((uint8_t *)&ip6hdr->ip6_src, sizeof(ip6hdr->ip6_src)).c_str(),
                         generate_addr_string((uint8_t *)&vlan_ipv6_gua, sizeof(vlan_ipv6_gua)).c_str(),
                         generate_addr_string((uint8_t *)&vlan_ipv6_lla, sizeof(vlan_ipv6_lla)).c_str(),
                         context->intf);

            is_valid = true;
            syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message valid, context interface %s", context->intf);
            break;
        }
        default:
            // should not reach here, as message type is already validated before
            syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: unknown dhcpv6 message type %d, context interface %s", dhcpv6_msg_type, context->intf);
            break;
    }

    syslog_debug(LOG_INFO, "check_dhcpv6_message_type_tx: dhcpv6 message check result %s on context interface %s", is_valid ? "valid" : "invalid", context->intf);

    return is_valid;
}

/**
 * Validate the checksum for IP headers
 * @param iphdr    Pointer to the IP header.
 * @return         True if the checksum is valid, false otherwise.
 */
static bool validate_ip_checksum(struct iphdr *iphdr){
    uint16_t orig_check = iphdr->check;
    iphdr->check = 0;
    uint16_t expected_checksum = calculate_ip_checksum(iphdr);
    iphdr->check = orig_check;
    if (ntohs(orig_check) != expected_checksum) {
        syslog_debug(LOG_WARNING, "validate_ip_checksum: ip checksum error, checksum in ip header: %d, calculated: %d", ntohs(orig_check), expected_checksum);
        return false;
    }
    syslog_debug(LOG_INFO, "validate_ip_checksum: ip checksum validation passed: checksum in ip header: %d", ntohs(orig_check));
    return true;
}

/**
 * Validate the checksum for IP headers and UDP packet. if the checksum is invalid, log warning and increase the drop packet counter.
 * @param udphdr   Pointer to the UDP header.
 * @param buffer   Pointer to the whole packet buffer (including IP header).
 * @param is_v6    True if the packet is IPv6, false if IPv4
 * @return         True if the checksum is valid, false otherwise.
 */
static bool validate_udp_checksum(struct udphdr *udphdr, const uint8_t *buffer, bool is_v6){
    uint16_t orig_uh_sum = udphdr->uh_sum;
    udphdr->uh_sum = 0;
    uint16_t expected_checksum = calculate_udp_checksum(udphdr, buffer + IP_START_OFFSET, is_v6);
    udphdr->uh_sum = orig_uh_sum;
    if (ntohs(orig_uh_sum) != expected_checksum) {
        syslog_debug(LOG_WARNING, "validate_udp_checksum: udp checksum error, checksum in udp: %d, calculated: %d", ntohs(orig_uh_sum), expected_checksum);
        return false;
    }
    syslog_debug(LOG_INFO, "validate_udp_checksum: udp checksum validation passed: checksum in udp: %d", ntohs(orig_uh_sum));
    return true;
}

/**
 * @code should_ignore_rx_packet(intf, context);
 * @brief ignore when intf is dualtor downlink context interface or standby physical interface
 * @return boolean
 */
static bool should_ignore_rx_packet(const std::string &ifname, const dhcp_device_context_t *context)
{
    return dual_tor_mode && context->is_downlink && (ifname == context->intf || intf_is_standby(ifname));
}

/**
 * @code should_dup_rx_packet(intf, context);
 * @brief duplicate rx packet when intf is different from context interface and not standby physical interface
 * @return boolean
 */
static bool should_dup_rx_packet(const std::string &ifname, const dhcp_device_context_t *context)
{
    return dual_tor_mode && context->is_downlink && ifname != context->intf && !intf_is_standby(ifname);
}

/**
 * @code find_dhcp_option_53(dhcp_options, dhcp_options_sz);
 *
 * @brief loop though dhcp options to find option with tag 53
 *
 * @return pointer to option 53 value if found (not including tag and length), NULL if not found
 */
static const uint8_t* find_dhcp_option_53(const uint8_t *dhcp_options, ssize_t dhcp_options_sz)
{
    ssize_t offset = 0;
    uint8_t tag, len;

    syslog_debug(LOG_INFO, "find_dhcp_option_53: searching dhcp options data of total size %zd for option 53", dhcp_options_sz);

    while (offset < dhcp_options_sz && dhcp_options[offset] != OPTION_DHCP_MESSAGE_END) {
        tag = dhcp_options[offset];
        if (tag == 0) {
            offset++;
            continue;
        }
        if (offset + 1 == dhcp_options_sz) {
            syslog_debug(LOG_WARNING, "find_dhcp_option_53: dhcp options has tag %d but no len, dhcp option is invalid", tag);
            return NULL;
        }
        len = dhcp_options[offset + 1];
        if (offset + 2 + len > dhcp_options_sz) {
            syslog_debug(LOG_WARNING, "find_dhcp_option_53: dhcp options has tag %d len %d but no space for value", tag, len);
            return NULL;
        }
        if (tag == OPTION_DHCP_MESSAGE_TYPE) {
            syslog_debug(LOG_INFO, "find_dhcp_option_53: found option 53 with length %d", len);
            return dhcp_options + offset + 2;
        }
        offset += 2 + len;
    }

    syslog_debug(LOG_WARNING, "find_dhcp_option_53: did not find option 53 in dhcp options");
    
    return NULL;
}

/**
 * @code ip_sanity_check(ifname, iphdr, buffer_sz, check_checksum);
 * @brief perform basic sanity check for received ip packet.
 * @param ifname            interface name
 * @param iphdr             pointer to IP header
 * @param buffer_sz         size of the received buffer
 * @param check_checksum    whether to check IP checksum, we do not check for tx packets
 * @return                  true if valid, false otherwise
 */
static bool ip_sanity_check(const std::string &ifname, struct iphdr *iphdr, ssize_t buffer_sz, bool check_checksum)
{
    // first to make sure this is large enough to include iphdr, udphdr and dhcphdr (up until the options part)
    if (buffer_sz < DHCP_OPTIONS_START_OFFSET) {
        syslog_debug(LOG_WARNING, "ip_sanity_check: received buffer_sz %zd is too small to include dhcp header, interface %s",
                     buffer_sz, ifname.c_str());
        return false;
    }
    syslog_debug(LOG_INFO, "ip_sanity_check: received buffer_sz %zd large enough to include dhcp header, interface %s",
                 buffer_sz, ifname.c_str());

    // We expect ip header to just be normal size, it CAN contain other options but we ignore it for now
    if (iphdr->ihl * 4 != sizeof(struct iphdr)) {
        syslog_debug(LOG_WARNING, "ip_sanity_check: received ip packet with header size %zd, expect standard ip header size %zd, interface %s",
                     iphdr->ihl * 4, sizeof(struct iphdr), ifname.c_str());
        return false;
    }
    syslog_debug(LOG_INFO, "ip_sanity_check: received ip packet with standard ip header size %zd, interface %s",
                 sizeof(struct iphdr), ifname.c_str());

    // iphdr tot_len is the length of the ip packet including iphdr and payload
    if (ntohs(iphdr->tot_len) < DHCP_OPTIONS_START_OFFSET - IP_START_OFFSET) {
        syslog_debug(LOG_WARNING, "ip_sanity_check: received ip packet size %zd is too small to include dhcp header, interface %s",
                     ntohs(iphdr->tot_len), ifname.c_str());
        return false;
    }
    syslog_debug(LOG_INFO, "ip_sanity_check: received ip packet size %d, interface %s", ntohs(iphdr->tot_len), ifname.c_str());

    if (check_checksum && !validate_ip_checksum(iphdr)) {
        syslog_debug(LOG_WARNING, "ip_sanity_check: ip checksum validation failed: interface %s", ifname.c_str());
        return false;
    }
    syslog_debug(LOG_INFO, "ip_sanity_check: ip checksum validation passed: interface %s", ifname.c_str());

    return true;
}

/**
 * @code ipv6_sanity_check(ifname, buffer, buffer_sz);
 * @brief perform basic sanity check for received ipv6 packet, and look for udp header
 * @param ifname        interface name
 * @param buffer        pointer to the received buffer
 * @param buffer_sz     size of the received buffer
 * @return pointer to udp header if success, NULL if not valid
 */
static struct udphdr* ipv6_sanity_check(const std::string &ifname, const uint8_t *buffer, ssize_t buffer_sz)
{
    struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(buffer + IP_START_OFFSET);
    
    // first to make sure there is an ipv6 header
    if (buffer_sz < IP_START_OFFSET + sizeof(struct ip6_hdr)) {
        syslog_debug(LOG_WARNING, "ipv6_sanity_check: received buffer_sz %zd is too small to include ipv6 header, interface %s", buffer_sz, ifname.c_str());
        return NULL;
    }
    syslog_debug(LOG_INFO, "ipv6_sanity_check: received buffer_sz %zd large enough to include ipv6 header, interface %s", buffer_sz, ifname.c_str());

    // then make sure the buffer contains the ipv6 packet
    if (buffer_sz < IP_START_OFFSET + sizeof(struct ip6_hdr) + ntohs(ip6hdr->ip6_plen)) {
        syslog_debug(LOG_WARNING, "ipv6_sanity_check: received buffer_sz %zd is smaller than ipv6 header size %zd plus payload size %d, interface %s",
                     buffer_sz, sizeof(struct ip6_hdr), ntohs(ip6hdr->ip6_plen), ifname.c_str());
        return NULL;
    }
    syslog_debug(LOG_INFO, "ipv6_sanity_check: received buffer size %zd is sufficient for ipv6 header size %zd plus payload size %d, interface %s",
                 buffer_sz, sizeof(struct ip6_hdr), ntohs(ip6hdr->ip6_plen), ifname.c_str());

    const uint8_t *nxt_hdr = buffer + IP_START_OFFSET + sizeof(struct ip6_hdr);
    if (ip6hdr->ip6_nxt != IPPROTO_UDP) {
        syslog_debug(LOG_INFO, "ipv6_sanity_check: received ipv6 packet with non-udp next header %d, check extension headers, interface %s",
                     ip6hdr->ip6_nxt, ifname.c_str());
        while (nxt_hdr - buffer + 8 <= buffer_sz && nxt_hdr[0] != IPPROTO_UDP && nxt_hdr[0] != IPPROTO_NONE) {
            syslog_debug(LOG_INFO, "ipv6_sanity_check: received ipv6 packet with extension header %d, interface %s", nxt_hdr[0], ifname.c_str());
            nxt_hdr += (nxt_hdr[1] + 1) * 8;
        }
        if (nxt_hdr - buffer >= buffer_sz || nxt_hdr[0] != IPPROTO_UDP) {
            syslog_debug(LOG_WARNING, "ipv6_sanity_check: received ipv6 packet with no udp header, interface %s", ifname.c_str());
            return NULL;
        }
        nxt_hdr += (nxt_hdr[1] + 1) * 8;
    }
    syslog_debug(LOG_INFO, "ipv6_sanity_check: found udp header in ipv6 packet, interface %s", ifname.c_str());

    return (struct udphdr *)nxt_hdr;
}

/**
 * @code pre_dhcp_sanity_check(ifname, iphdr, udphdr, buffer, buffer_sz, is_v6, check_checksum);
 * @brief perform basic size check for received packet.
 * @param ifname            interface name
 * @param iphdr             pointer to IP header
 * @param udphdr            pointer to UDP header
 * @param buffer            pointer to the received buffer
 * @param buffer_sz         size of the received buffer
 * @param is_v6             whether the packet is IPv6
 * @param check_checksum    whether to check IP and UDP checksums, checksum calculation is often offloaded to nic with tx packets, so we skip it with tx
 * @return                  true if valid, false otherwise
 */
static bool udp_sanity_check(const std::string &ifname, struct udphdr *udphdr, const uint8_t *buffer, ssize_t buffer_sz, bool is_v6, bool check_checksum)
{
    // udphdr len is the length of the udp packet including the udphdr and payload
    if (ntohs(udphdr->len) < sizeof(struct udphdr) + (is_v6 ? DHCPV6_HEADER_SIZE : DHCP_HEADER_SIZE)) {
        syslog_debug(LOG_WARNING, "udp_sanity_check: received udp packet size %d is too small to include dhcp header size %zd, interface %s",
                     ntohs(udphdr->len), is_v6 ? DHCPV6_HEADER_SIZE : DHCP_HEADER_SIZE, ifname.c_str());
        return false;
    }
    syslog_debug(LOG_INFO, "udp_sanity_check: received udp packet size %d, interface %s",
                 ntohs(udphdr->len), ifname.c_str());

    if (buffer_sz < ntohs(udphdr->len) + ((uint8_t *)udphdr - buffer)) {
        syslog_debug(LOG_WARNING, "udp_sanity_check: received udp packet size %d plus ip/ipv6 header size exceed buffer size %d, interface %s",
                     ntohs(udphdr->len), buffer_sz, ifname.c_str());
        return false;
    }
    syslog_debug(LOG_INFO, "udp_sanity_check: received udp packet size %d plus ip/ipv6 header size within buffer size %d, interface %s",
                 ntohs(udphdr->len), buffer_sz, ifname.c_str());

    if (check_checksum && !validate_udp_checksum(udphdr, buffer, is_v6)) {
        syslog_debug(LOG_WARNING, "udp_sanity_check: udp checksum validation failed: interface %s", ifname.c_str());
        return false;
    }
    syslog_debug(LOG_INFO, "udp_sanity_check: udp checksum validation passed: interface %s", ifname.c_str());

    return true;
}

/**
 * @code get_dhcp_options_sz(udphdr, buffer_sz);
 *
 * @brief calculate dhcp options size from udp header and buffer size
 *
 * @return dhcp options size
 */
static ssize_t get_dhcp_options_sz(const struct udphdr *udphdr, ssize_t buffer_sz)
{
    // potential dhcp_options_sz can be calculated from udp len - udp hdr len and buffer_sz - all headers, and we pick the smaller
    ssize_t dhcp_sz = ntohs(udphdr->len) - sizeof(struct udphdr) < buffer_sz - DHCP_START_OFFSET ?
                      ntohs(udphdr->len) - sizeof(struct udphdr) : buffer_sz - DHCP_START_OFFSET;
    return dhcp_sz - DHCP_HEADER_SIZE;
}

/**
 * @code dhcpv6_sanity_check(ifname, dhcp6hdr, dhcp6_options, dhcp6_options_sz);
 *
 * @brief loop though dhcpv6 options to perform sanity check. If relay message option is found, recursively check inner dhcpv6 packet.
 *
 * @return true if valid, false otherwise
 */
static bool dhcpv6_sanity_check(const std::string &ifname, const uint8_t *dhcp6hdr, const uint8_t *dhcp6_options, ssize_t dhcp6_options_sz)
{
    ssize_t offset = 0;
    uint16_t code, len;

    while (offset + 1 < dhcp6_options_sz) {
        code = ntohs(*(uint16_t *)(dhcp6_options + offset));
        if (code > DHCPV6_OPTION_CODE_MAX) {
            syslog_debug(LOG_WARNING, "dhcpv6_sanity_check: invalid dhcp option code %d, should be no larger than %d, interface %s", code, DHCPV6_OPTION_CODE_MAX, ifname.c_str());
            return false;
        }
        syslog_debug(LOG_INFO, "dhcpv6_sanity_check: dhcpv6 option code %d in dhcp packet, interface %s", code, ifname.c_str());
        if (offset + 3 >= dhcp6_options_sz) {
            syslog_debug(LOG_WARNING, "dhcpv6_sanity_check: invalid dhcp options: dhcpv6 options has code but no len, interface %s", ifname.c_str());
            return false;
        }
        len = ntohs(*(uint16_t *)(dhcp6_options + offset + 2));
        if (offset + 4 + len > dhcp6_options_sz) {
            syslog_debug(LOG_WARNING, "dhcpv6_sanity_check: invalid dhcp options: dhcp options has no space for value, interface %s", ifname.c_str());
            return false;
        }
        syslog_debug(LOG_INFO, "dhcpv6_sanity_check: dhcpv6 option code %d has length %d, interface %s", code, len, ifname.c_str());
        if (code == OPTION_DHCPV6_RELAY_MSG) {
            syslog_debug(LOG_INFO, "dhcpv6_sanity_check: dhcpv6 option code %d is a relay message, interface %s", code, ifname.c_str());
            const uint8_t *inner_dhcp6hdr = dhcp6_options + offset + 4;
            uint8_t inner_msg_type = *inner_dhcp6hdr;
            const uint8_t *inner_dhcp6_options = inner_dhcp6hdr + (inner_msg_type < DHCPV6_MESSAGE_TYPE_RELAY_FORW ? DHCPV6_HEADER_SIZE : DHCPV6_RELAY_HEADER_SIZE);
            if (!dhcpv6_sanity_check(ifname, inner_dhcp6hdr, inner_dhcp6_options, len - (inner_dhcp6_options - inner_dhcp6hdr))) {
                syslog_debug(LOG_WARNING, "dhcpv6_sanity_check: invalid inner dhcpv6 packet, interface %s", ifname.c_str());
                return false;
            }
            syslog_debug(LOG_INFO, "dhcpv6_sanity_check: valid inner dhcpv6 packet, interface %s", ifname.c_str());
        }
        offset += 4 + len;
    }

    return true;
}

/**
 * @code client_packet_handler(ifname, context, buffer, buffer_sz);
 * @brief packet handler to process received rx
 * @param ifname        socket interface
 * @param context       pointer to device (interface) context
 * @param buffer_sz     size of the received buffer
 * @return none
 */
void rx_packet_handler(const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz)
{
    sock_info_t &sock_info = sock_mgr_get_sock_info(rx_sock);
    
    syslog_debug(LOG_INFO, "rx_packet_handler: handle packet on interface %s, context %s, buffer size %zd", ifname.c_str(), context->intf, buffer_sz);
    
    // handler will be invoked for physical interface and context interface, so both counters will be updated
    // For single tor and dualtor uplink, no special care is needed
    // For dualtor, rx packets come from downlink standby interfaces will be dropped, hence directly
    // to prevent mis-count, on dualtor downlink
    //   - Ignore packet captured in context interface and standby physical interface
    //   - When capture packet in non-standby physical interface, update context interface and physical
    //     interface count together
    if (should_ignore_rx_packet(ifname, context)) {
        syslog_debug(LOG_INFO, "rx_packet_handler: ignore packet on interface %s, context %s, because is dual tor downlink standby interface",
                     ifname.c_str(), context->intf);
        return;
    }

    bool dup_to_context = should_dup_rx_packet(ifname, context);
    syslog_debug(LOG_INFO, "rx_packet_handler: duplicate packet from %s to context interface %s: %s",
                 ifname.c_str(), context->intf, dup_to_context ? "yes" : "no");

    uint8_t *buffer = sock_info.buffer;
    struct iphdr *iphdr = (struct iphdr* )(buffer + IP_START_OFFSET);
    if (!ip_sanity_check(ifname, iphdr, buffer_sz, true)) {
        syslog_debug(LOG_WARNING, "rx_packet_handler: packet is not valid ip packet, interface %s, context %s, silent drop",
                     ifname.c_str(), context->intf);
        syslog_debug(LOG_WARNING, "rx_packet_handler: %s", generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, rx_sock, DHCP_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iphdr->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iphdr->daddr, dst_ip, INET_ADDRSTRLEN);
    syslog_debug(LOG_INFO, "rx_packet_handler: ip sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    struct udphdr *udphdr = (struct udphdr*) (buffer + UDP_START_OFFSET);
    if (!udp_sanity_check(ifname, udphdr, buffer, buffer_sz, false, true)) {
        syslog_debug(LOG_WARNING, "rx_packet_handler: packet is not valid udp packet, interface %s, context %s, src ip %s, dst ip %s, silent drop",
                     ifname.c_str(), context->intf, src_ip, dst_ip);
        syslog_debug(LOG_WARNING, "rx_packet_handler: %s", generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, rx_sock, DHCP_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler: udp sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    if (buffer_sz > DHCP_START_OFFSET + DHCP_MTU_MIN) {
        syslog_debug(LOG_WARNING, "rx_packet_handler: buffer_sz %zd exceeds expectation, interface %s, context %s, src ip %s, dst ip %s",
                     buffer_sz, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock, DHCP_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler: buffer_sz check passed, buffer_sz %zd, interface %s, context %s, src ip %s, dst ip %s",
                 buffer_sz, ifname.c_str(), context->intf, src_ip, dst_ip);

    // when magic cookie doesnt match, it can either be bootp msg or malformed
    uint32_t magic_cookie = ntohl(*((uint32_t *)(buffer + DHCP_MAGIC_COOKIE_OFFSET)));
    if (magic_cookie != DHCP_MAGIC_COOKIE) {
        syslog_debug(LOG_WARNING, "rx_packet_handler: magic cookie mismatch, interface %s, context %s, src ip %s, dst ip %s, magic cookie in packet: 0x%X",
                     ifname.c_str(), context->intf, src_ip, dst_ip, magic_cookie);
        increase_cache_counter(ifname, context, rx_sock, DHCP_MESSAGE_TYPE_BOOTP, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler: magic cookie check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    const uint8_t *dhcp_option_53;
    if ((dhcp_option_53 = find_dhcp_option_53(buffer + DHCP_OPTIONS_START_OFFSET, get_dhcp_options_sz(udphdr, buffer_sz))) == NULL) {
        syslog_debug(LOG_WARNING, "rx_packet_handler: cannot find option 53 value in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock, DHCP_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler: found option 53 value %d in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                 *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);

    if (*dhcp_option_53 > DHCP_MESSAGE_TYPE_INFORM) {
        syslog_debug(LOG_WARNING, "rx_packet_handler: unknown option 53 value %d in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock, DHCP_MESSAGE_TYPE_UNKNOWN, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler: option 53 value %d valid, interface %s, context %s, src ip %s, dst ip %s",
                 *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);

    if (check_dhcp_option_53_rx(*dhcp_option_53, context, iphdr, buffer)) {
        syslog_debug(LOG_INFO, "rx_packet_handler: option 53 value %d check passed, interface %s, context %s, src ip %s, dst ip %s",
                     *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock, *dhcp_option_53, dup_to_context);
        return;
    } else {
        syslog_debug(LOG_WARNING, "rx_packet_handler: option 53 value %d check failed, interface %s, context %s, src ip %s, dst ip %s",
                     *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock, DHCP_MESSAGE_TYPE_DROPPED, dup_to_context);
        return;
    }
}

/**
 * @code tx_packet_handler(ifname, context, buffer, buffer_sz);
 * @brief packet handler to process transmitted tx packets. compared to rx, since we are the one sending
 *       out the packets, we can be more lenient on some checks like packet size.
 * @param ifname        socket interface
 * @param context       pointer to device (interface) context
 * @param buffer_sz     size of the received buffer
 *
 * @return none
 */
void tx_packet_handler(const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz)
{
    sock_info_t &sock_info = sock_mgr_get_sock_info(tx_sock);
    
    syslog_debug(LOG_INFO, "tx_packet_handler: handle packet on interface %s, context %s, buffer size %zd", ifname.c_str(), context->intf, buffer_sz);

    uint8_t *buffer = sock_info.buffer;
    struct iphdr *iphdr = (struct iphdr *)(buffer + IP_START_OFFSET);
    if (!ip_sanity_check(ifname, iphdr, buffer_sz, false)) {
        syslog_debug(LOG_WARNING, "tx_packet_handler: packet is not valid ip packet, interface %s, context %s, silent drop",
                     ifname.c_str(), context->intf);
        syslog_debug(LOG_WARNING, "tx_packet_handler: %s", generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, tx_sock, DHCP_MESSAGE_TYPE_MALFORMED);
        return;
    }
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iphdr->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iphdr->daddr, dst_ip, INET_ADDRSTRLEN);
    syslog_debug(LOG_INFO, "tx_packet_handler: ip sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    struct udphdr *udphdr = (struct udphdr*) (buffer + UDP_START_OFFSET);
    if (!udp_sanity_check(ifname, udphdr, buffer, buffer_sz, false, false)) {
        syslog_debug(LOG_WARNING, "tx_packet_handler: packet is not valid udp packet, interface %s, context %s, src ip %s, dst ip %s, silent drop",
                     ifname.c_str(), context->intf, src_ip, dst_ip);
        syslog_debug(LOG_WARNING, "tx_packet_handler: %s", generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, tx_sock, DHCP_MESSAGE_TYPE_MALFORMED);
        return;
    }
    syslog_debug(LOG_INFO, "tx_packet_handler: udp sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    // when magic cookie doesnt match, it can either be bootp msg or malformed
    uint32_t magic_cookie = ntohl(*((uint32_t *)(buffer + DHCP_MAGIC_COOKIE_OFFSET)));
    if (magic_cookie != DHCP_MAGIC_COOKIE) {
        syslog_debug(LOG_WARNING, "tx_packet_handler: magic cookie mismatch, interface %s, context %s, src ip %s, dst ip %s, magic cookie in packet: 0x%X",
                     ifname.c_str(), context->intf, src_ip, dst_ip, magic_cookie);
        increase_cache_counter(ifname, context, tx_sock, DHCP_MESSAGE_TYPE_BOOTP);
        return;
    }
    syslog_debug(LOG_INFO, "tx_packet_handler: magic cookie check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    const uint8_t *dhcp_option_53;
    if ((dhcp_option_53 = find_dhcp_option_53(buffer + DHCP_OPTIONS_START_OFFSET, get_dhcp_options_sz(udphdr, buffer_sz))) == NULL) {
        syslog_debug(LOG_WARNING, "tx_packet_handler: cannot find option 53 value in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, tx_sock, DHCP_MESSAGE_TYPE_MALFORMED);
        return;
    }

    if (*dhcp_option_53 > DHCP_MESSAGE_TYPE_INFORM) {
        syslog_debug(LOG_WARNING, "tx_packet_handler: unknown option 53 value %d in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, tx_sock, DHCP_MESSAGE_TYPE_UNKNOWN);
        return;
    }
    syslog_debug(LOG_INFO, "tx_packet_handler: option 53 value %d valid, interface %s, context %s, src ip %s, dst ip %s",
                 *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);

    if (check_dhcp_option_53_tx(*dhcp_option_53, context, iphdr, buffer)) {
        syslog_debug(LOG_INFO, "tx_packet_handler: option 53 value %d check passed, interface %s, context %s, src ip %s, dst ip %s",
                     *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, tx_sock, *dhcp_option_53);
        return;
    } else {
        syslog_debug(LOG_WARNING, "tx_packet_handler: option 53 value %d check failed, interface %s, context %s, src ip %s, dst ip %s",
                     *dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, tx_sock, DHCP_MESSAGE_TYPE_DROPPED);
        return;
    }
}

/**
 * @code  rx_packet_handler_v6(ifname, context, buffer_sz);
 * @brief packet handler to process received rx ipv6 packets
 * @param ifname        socket interface
 * @param context       pointer to device (interface) context
 * @param buffer_sz     size of the received buffer
 * @return none
 */
void rx_packet_handler_v6(const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz)
{
    sock_info_t &sock_info = sock_mgr_get_sock_info(rx_sock_v6);

    syslog_debug(LOG_INFO, "rx_packet_handler_v6: handle packet on interface %s, context %s, buffer size %zd", ifname.c_str(), context->intf, buffer_sz);

    if (should_ignore_rx_packet(ifname, context)) {
        syslog_debug(LOG_INFO, "rx_packet_handler_v6: ignore packet on interface %s, context %s, because is dual tor downlink standby interface",
                     ifname.c_str(), context->intf);
        return;
    }

    bool dup_to_context = should_dup_rx_packet(ifname, context);
    syslog_debug(LOG_INFO, "rx_packet_handler_v6: duplicate packet from %s to context interface %s: %s",
                 ifname.c_str(), context->intf, dup_to_context ? "yes" : "no");

    uint8_t *buffer = sock_info.buffer;
    struct udphdr *udphdr;
    if ((udphdr = ipv6_sanity_check(ifname, buffer, buffer_sz)) == NULL) {
        syslog_debug(LOG_WARNING, "rx_packet_handler_v6: packet is not valid ipv6 packet with udp header, interface %s, context %s, silent drop",
                     ifname.c_str(), context->intf);
        syslog_debug(LOG_WARNING, "rx_packet_handler_v6: %s", generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, rx_sock_v6, DHCPV6_MESSAGE_TYPE_MALFORMED,  dup_to_context);
        return;
    }
    struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(buffer + IP_START_OFFSET);
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6hdr->ip6_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &ip6hdr->ip6_dst, dst_ip, sizeof(dst_ip));
    syslog_debug(LOG_INFO, "rx_packet_handler_v6: ipv6 sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);
                 
    if (!udp_sanity_check(ifname, udphdr, buffer, buffer_sz, true, true)) {
        syslog_debug(LOG_WARNING, "rx_packet_handler_v6: packet is not valid udp packet, interface %s, context %s, src ip %s, dst ip %s",
                     ifname.c_str(), context->intf, src_ip, dst_ip);
        syslog_debug(LOG_WARNING, "rx_packet_handler_v6: %s", generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, rx_sock_v6, DHCPV6_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler_v6: udp sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    if (buffer_sz > (uint8_t *)udphdr - buffer + sizeof(struct udphdr) + DHCPV6_MTU_MIN) {
        syslog_debug(LOG_WARNING, "rx_packet_handler_v6: received packet size %zd exceeds expectation, interface %s, context %s, src ip %s, dst ip %s",
                     buffer_sz, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock_v6, DHCPV6_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler_v6: buffer_sz check passed, buffer_sz %zd, interface %s, context %s, src ip %s, dst ip %s",
                 buffer_sz, ifname.c_str(), context->intf, src_ip, dst_ip);

    uint8_t *dhcp6hdr = (uint8_t *)udphdr + sizeof(struct udphdr);
    uint8_t msg_type = *dhcp6hdr;
    if (msg_type > DHCPV6_MESSAGE_TYPE_RELAY_REPL) {
        syslog_debug(LOG_WARNING, "rx_packet_handler_v6: unknown dhcpv6 message type value %d in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock_v6, DHCPV6_MESSAGE_TYPE_UNKNOWN, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler_v6: dhcpv6 message type %d valid, interface %s, context %s, src ip %s, dst ip %s",
                 msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);

    uint8_t *dhcp6_options = dhcp6hdr + (msg_type < DHCPV6_MESSAGE_TYPE_RELAY_FORW ? DHCPV6_HEADER_SIZE : DHCPV6_RELAY_HEADER_SIZE);
    ssize_t dhcp6_sz = ntohs(udphdr->len) - sizeof(struct udphdr) < buffer_sz - (dhcp6hdr - buffer) ?
                       ntohs(udphdr->len) - sizeof(struct udphdr) : buffer_sz - (dhcp6hdr - buffer);
    ssize_t dhcp6_options_sz = dhcp6_sz - (dhcp6_options - dhcp6hdr);

    if (!dhcpv6_sanity_check(ifname, dhcp6hdr, dhcp6_options, dhcp6_options_sz)) {
        syslog_debug(LOG_WARNING, "rx_packet_handler_v6: dhcpv6 packet sanity check failed, interface %s, context %s, src ip %s, dst ip %s",
                     ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock_v6, DHCPV6_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "rx_packet_handler_v6: dhcpv6 sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    if (check_dhcpv6_message_type_rx(msg_type, context, ip6hdr, dhcp6hdr, dhcp6_options, dhcp6_options_sz)) {
        syslog_debug(LOG_INFO, "rx_packet_handler_v6: dhcpv6 message type %d check passed, interface %s, context %s, src ip %s, dst ip %s",
                     msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock_v6, msg_type, dup_to_context);
        return;
    } else {
        syslog_debug(LOG_WARNING, "rx_packet_handler_v6: dhcpv6 message type %d check failed, interface %s, context %s, src ip %s, dst ip %s",
                     msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, rx_sock_v6, DHCPV6_MESSAGE_TYPE_DROPPED, dup_to_context);
        return;
    }
}

/**
 * @code  tx_packet_handler_v6(ifname, context, buffer_sz);
 * @brief packet handler to process transmitted tx ipv6 packets. compared to rx, since we are the one sending
 *        out the packets, we can be more lenient on some checks like packet size.
 * @param ifname        socket interface
 * @param context       pointer to device (interface) context
 * @param buffer_sz     size of the received buffer
 * @return none
 */
void tx_packet_handler_v6(const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz)
{
    sock_info_t &sock_info = sock_mgr_get_sock_info(tx_sock_v6);

    syslog_debug(LOG_INFO, "tx_packet_handler_v6: handle packet on interface %s, context %s, buffer size %zd", ifname.c_str(), context->intf, buffer_sz);

    uint8_t *buffer = sock_info.buffer;
    struct udphdr *udphdr;
    if ((udphdr = ipv6_sanity_check(ifname, buffer, buffer_sz)) == NULL) {
        syslog_debug(LOG_WARNING, "tx_packet_handler_v6: packet is not valid ipv6 packet with udp header, interface %s, context %s", ifname.c_str(), context->intf);
        syslog_debug(LOG_WARNING, "tx_packet_handler_v6: %s", generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, tx_sock_v6, DHCPV6_MESSAGE_TYPE_MALFORMED);
        return;
    }
    struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(buffer + IP_START_OFFSET);
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6hdr->ip6_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &ip6hdr->ip6_dst, dst_ip, sizeof(dst_ip));
    syslog_debug(LOG_INFO, "tx_packet_handler_v6: ipv6 sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    if (!udp_sanity_check(ifname, udphdr, buffer, buffer_sz, true, false)) {
        syslog_debug(LOG_WARNING, "tx_packet_handler_v6: packet is not valid udp packet, interface %s, context %s, src ip %s, dst ip %s",
                     ifname.c_str(), context->intf, src_ip, dst_ip);
        syslog_debug(LOG_WARNING, "tx_packet_handler_v6: %s", generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, tx_sock_v6, DHCPV6_MESSAGE_TYPE_MALFORMED);
        return;
    }
    syslog_debug(LOG_INFO, "tx_packet_handler_v6: udp sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    uint8_t *dhcp6hdr = (uint8_t *)udphdr + sizeof(struct udphdr);
    uint8_t msg_type = *dhcp6hdr;
    if (msg_type > DHCPV6_MESSAGE_TYPE_RELAY_REPL) {
        syslog_debug(LOG_WARNING, "tx_packet_handler_v6: unknown dhcpv6 message type value %d in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, tx_sock_v6, DHCPV6_MESSAGE_TYPE_UNKNOWN);
        return;
    }
    syslog_debug(LOG_INFO, "tx_packet_handler_v6: dhcpv6 message type %d valid, interface %s, context %s, src ip %s, dst ip %s",
                 msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);

    uint8_t *dhcp6_options = dhcp6hdr + (msg_type < DHCPV6_MESSAGE_TYPE_RELAY_FORW ? DHCPV6_HEADER_SIZE : DHCPV6_RELAY_HEADER_SIZE);
    ssize_t dhcp6_sz = ntohs(udphdr->len) - sizeof(struct udphdr) < buffer_sz - (dhcp6hdr - buffer) ?
               ntohs(udphdr->len) - sizeof(struct udphdr) : buffer_sz - (dhcp6hdr - buffer);
    ssize_t dhcp6_options_sz = dhcp6_sz - (dhcp6_options - dhcp6hdr);

    if (!dhcpv6_sanity_check(ifname, dhcp6hdr, dhcp6_options, dhcp6_options_sz)) {
        syslog_debug(LOG_WARNING, "tx_packet_handler_v6: dhcpv6 packet sanity check failed, interface %s, context %s, src ip %s, dst ip %s",
                     ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, tx_sock_v6, DHCPV6_MESSAGE_TYPE_MALFORMED);
        return;
    }
    syslog_debug(LOG_INFO, "tx_packet_handler_v6: dhcpv6 sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 ifname.c_str(), context->intf, src_ip, dst_ip);

    if (check_dhcpv6_message_type_tx(msg_type, context, ip6hdr, dhcp6hdr, dhcp6_options, dhcp6_options_sz)) {
        syslog_debug(LOG_INFO, "tx_packet_handler_v6: dhcpv6 message type %d check passed, interface %s, context %s, src ip %s, dst ip %s",
                     msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, tx_sock_v6, msg_type);
        return;
    } else {
        syslog_debug(LOG_WARNING, "tx_packet_handler_v6: dhcpv6 message type %d check failed, interface %s, context %s, src ip %s, dst ip %s",
                     msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, tx_sock_v6, DHCPV6_MESSAGE_TYPE_DROPPED);
        return;
    }
}

void callback_common(int fd, short event, void *arg)
{
    ssize_t buffer_sz;
    struct sockaddr_ll sll;
    socklen_t slen = sizeof(sll);
    sock_info_t &sock_info = sock_mgr_get_sock_info(fd);

    while ((buffer_sz = recvfrom(fd, sock_info.buffer, sock_info.snaplen, MSG_DONTWAIT, (struct sockaddr *)&sll, &slen)) > 0) 
    {
        char ifname_buf[IF_NAMESIZE];
        if (if_indextoname(sll.sll_ifindex, ifname_buf) == NULL) {
            syslog_debug(LOG_WARNING, "if_indextoname: invalid input interface index %d %s", sll.sll_ifindex, strerror(errno));
            continue;
        }
        std::string ifname = ifname_buf;
        const dhcp_device_context_t *context = dhcp_devman_get_device_context(ifname);
        syslog_debug(LOG_INFO, "callback_common: received packet on interface index %d, mapped to interface %s, mapped to context interface %s",
                     sll.sll_ifindex, ifname_buf, context ? context->intf : "NULL");
        if (context != NULL) {
            debug_mask = (ifname == context->intf) && (ifname != mgmt_ifname);
            ((packet_handler_t)sock_info.packet_handler)(ifname, context, buffer_sz);
            debug_mask = true;
        }
    }
}