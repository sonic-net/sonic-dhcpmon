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

#include "sock_mgr.h"             /** to update to counter */
#include "dhcp_devman.h"          /** to get the interface info and context */
#include "dhcp_check_profile.h"   /** to get dhcp/v6 check profile */
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

    // we seperate mgmt interface from others and do not increase agg counter
    if (mgmt_ifname != "" && mgmt_ifname.compare(context->intf) == 0) {
        return;
    }

    // when ifname belongs to another context ifname, increase the aggregate counter for that context, 
    // else when ifname is the context, we increase agg counter for all.
    _increase_cache_counter(get_agg_counter_ifname(ifname, context->intf), sock, type);
    
    // optionally duplicate to context ifname, it will only be true when this is standby physical interface under a vlan on a dual tor
    if (dup_to_context) {
        increase_cache_counter(std::string(context->intf), context, sock, type);
    }
}

static bool check_dhcp_option_53(dhcp_msg_check_profile_t *profile, const dhcp_device_context_t *context, const struct iphdr *iphdr, const uint8_t *buffer)
{
    syslog_debug(LOG_INFO, "check_dhcp_option_53: checking dhcpv6 option 53, context interface %s", context->intf);

    // when profile is null, it means this msg type under the circumstance (i.e. direction) should not appear
    if (profile == NULL) {
        syslog_debug(LOG_WARNING, "check_dhcp_option_53: profile is NULL, unexpected packet, context interface %s, drop", context->intf);
        return false;
    }

    for (int i = 0; i < DHCP_CHECK_TYPE_COUNT; ++i) {
        dhcp_msg_check_type_t check_type = (dhcp_msg_check_type_t)i;
        // skip null profile entries
        if ((*profile)[check_type] == NULL) {
            continue;
        }
        syslog_debug(LOG_INFO, "check_dhcp_option_53: checking profile entry %s, context interface %s", get_check_type_desc(check_type), context->intf);
        switch (check_type) {
            case DHCP_CHECK_INTF_TYPE: {
                std::vector<dhcp_device_intf_t> *intf_types = (std::vector<dhcp_device_intf_t> *)(*profile)[check_type];
                if (!contains_value(*intf_types, context->intf_type)) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: interface type %s not in expected %s, context interface %s, drop",
                                 intf_type_name[context->intf_type],
                                 generate_vector_string(*intf_types, [](const dhcp_device_intf_t &type) { return intf_type_name[type]; }).c_str(),
                                 context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: interface type %s in expected %s, context interface %s",
                             intf_type_name[context->intf_type],
                             generate_vector_string(*intf_types, [](const dhcp_device_intf_t &type) { return intf_type_name[type]; }).c_str(),
                             context->intf);
                break;
            }
            case DHCP_CHECK_SRC_IP:
            case DHCP_CHECK_DST_IP:
            case DHCP_CHECK_GIADDR: {
                std::vector<const in_addr *> *ips = (std::vector<const in_addr *> *)(*profile)[check_type];
                const in_addr *packet_ip = check_type == DHCP_CHECK_SRC_IP ? (const in_addr *)&iphdr->saddr : check_type == DHCP_CHECK_DST_IP ? (const in_addr *)&iphdr->daddr :
                                                                             (const in_addr *)(buffer + DHCP_GIADDR_OFFSET);
                if (!contains_pointer(*ips, packet_ip)) {
                    syslog_debug(LOG_WARNING, "check_dhcp_option_53: %s ip %s not in expected %s, context interface %s, drop",
                                 check_type == DHCP_CHECK_SRC_IP ? "src" : check_type == DHCP_CHECK_DST_IP ? "dst" : "giaddr",
                                 generate_addr_string((const uint8_t *)packet_ip, sizeof(*packet_ip)).c_str(),
                                 generate_vector_string(*ips, [](const in_addr *addr) { return generate_addr_string((const uint8_t *)addr, sizeof(in_addr)); }).c_str(),
                                 context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcp_option_53: %s ip %s in expected %s, context interface %s",
                             check_type == DHCP_CHECK_SRC_IP ? "src" : check_type == DHCP_CHECK_DST_IP ? "dst" : "giaddr",
                             generate_addr_string((const uint8_t *)packet_ip, sizeof(*packet_ip)).c_str(),
                             generate_vector_string(*ips, [](const in_addr *addr) { return generate_addr_string((const uint8_t *)addr, sizeof(in_addr)); }).c_str(),
                             context->intf);
                break;
            }
            default: {
                syslog_debug(LOG_WARNING, "check_dhcp_message_type: unknown dhcp check type %d, context interface %s, drop", i, context->intf);
                return false;
            }
        }
    }

    syslog_debug(LOG_INFO, "check_dhcp_option_53: dhcp message check passed, context interface %s", context->intf);

    return true;
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
 * @code check_dhcpv6_message_type(profile, context, ip6hdr, dhcp6hdr, dhcp6_options, dhcp6_options_sz);
 * @brief check dhcpv6 message type against the given profile
 * @param profile           dhcpv6 message check profile
 * @param context           pointer to device context
 * @param ip6hdr            pointer to IPv6 header
 * @param dhcp6hdr          pointer to dhcpv6 header
 * @param dhcp6_options     pointer to dhcpv6 options buffer
 * @param dhcp6_options_sz  size of dhcpv6 options buffer
 * @return true if the message matches the profile, false otherwise
 */
static bool check_dhcpv6_message_type(dhcpv6_msg_check_profile_t *profile, const dhcp_device_context_t *context, const struct ip6_hdr *ip6hdr,
                                      const uint8_t *dhcp6hdr, const uint8_t *dhcp6_options, ssize_t dhcp6_options_sz)
{
    syslog_debug(LOG_INFO, "check_dhcpv6_message_type: checking dhcpv6 message type, context interface %s", context->intf);

    // when profile is null, it means this msg type under the circumstance (i.e. direction) should not appear
    if (profile == NULL) {
        syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: profile is NULL, unexpected packet, context interface %s, drop", context->intf);
        return false;
    }

    for (int i = 0; i < DHCPV6_CHECK_TYPE_COUNT; ++i) {
        dhcpv6_msg_check_type_t check_type = (dhcpv6_msg_check_type_t)i;
        // skip null profile entries
        if ((*profile)[check_type] == NULL) {
            continue;
        }
        syslog_debug(LOG_INFO, "check_dhcpv6_message_type: checking profile entry %s, context interface %s", get_check_type_desc_v6(check_type), context->intf);
        switch (check_type) {
            case DHCPV6_CHECK_INTF_TYPE: {
                std::vector<dhcp_device_intf_t> *intf_types = (std::vector<dhcp_device_intf_t> *)(*profile)[check_type];
                if (!contains_value(*intf_types, context->intf_type)) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: interface type %s not in expected %s, context interface %s, drop",
                                 intf_type_name[context->intf_type],
                                 generate_vector_string(*intf_types, [](const dhcp_device_intf_t &type) { return intf_type_name[type]; }).c_str(),
                                 context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: interface type %s in expected %s, context interface %s",
                             intf_type_name[context->intf_type],
                             generate_vector_string(*intf_types, [](const dhcp_device_intf_t &type) { return intf_type_name[type]; }).c_str(),
                             context->intf);
                break;
            }
            case DHCPV6_CHECK_SRC_IP:
            case DHCPV6_CHECK_DST_IP: {
                std::vector<const in6_addr *> *ips = (std::vector<const in6_addr *> *)(*profile)[check_type];
                if (!contains_pointer(*ips, check_type == DHCPV6_CHECK_SRC_IP ? (const in6_addr *)&ip6hdr->ip6_src : (const in6_addr *)&ip6hdr->ip6_dst)) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: %s ip %s not in expected %s, context interface %s, drop",
                                 check_type == DHCPV6_CHECK_SRC_IP ? "src" : "dst",
                                 generate_addr_string(check_type == DHCPV6_CHECK_SRC_IP ? (const uint8_t *)&ip6hdr->ip6_src : (const uint8_t *)&ip6hdr->ip6_dst, sizeof(in6_addr)).c_str(),
                                 generate_vector_string(*ips, [](const in6_addr *addr) { return generate_addr_string((const uint8_t *)addr, sizeof(in6_addr)); }).c_str(),
                                 context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: %s ip %s in expected %s, context interface %s",
                             check_type == DHCPV6_CHECK_SRC_IP ? "src" : "dst",
                             generate_addr_string(check_type == DHCPV6_CHECK_SRC_IP ? (const uint8_t *)&ip6hdr->ip6_src : (const uint8_t *)&ip6hdr->ip6_dst, sizeof(in6_addr)).c_str(),
                             generate_vector_string(*ips, [](const in6_addr *addr) { return generate_addr_string((const uint8_t *)addr, sizeof(in6_addr)); }).c_str(),
                             context->intf);
                break;
            }
            case DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY:
            case DHCPV6_CHECK_LINK_ADDR_INNER_MSG_NOT_RELAY: {
                if ((*profile)[DHCPV6_CHECK_HAS_RELAY_OPT] == NULL || *((bool *)(*profile)[DHCPV6_CHECK_HAS_RELAY_OPT]) == false) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: inconsistent profile, has_relay_opt is null or false while checking link address, context interface %s, drop",
                                 context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: has_relay_opt is true and fallthrough to %s for link address check, context interface %s",
                             get_check_type_desc_v6(DHCPV6_CHECK_HAS_RELAY_OPT), context->intf);
            }
            // has_relay_opt will be run in 2 cases, first when it's own, second when there is fallthrough from the above case
            // for the first case the pointer is guaranteed to be not null due to the check at the beginning of the loop
            // for the second case, we have an implicit guarantee from the above case that the relay check has to exist and also be true
            case DHCPV6_CHECK_HAS_RELAY_OPT: {
                bool has_relay_opt = *((bool *)(*profile)[DHCPV6_CHECK_HAS_RELAY_OPT]);
                const uint8_t *option_relay_msg = find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, dhcp6_options, dhcp6_options_sz);
                if ((option_relay_msg != NULL) != has_relay_opt) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: relay msg option status not expected in dhcpv6 options, expect %s, get %s, context interface %s, drop",
                                 has_relay_opt ? "present" : "not present", option_relay_msg != NULL ? "present" : "not present", context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: relay msg option status as expected in dhcpv6 options, expect %s, get %s, context interface %s",
                             has_relay_opt ? "present" : "not present", option_relay_msg != NULL ? "present" : "not present", context->intf);
                // if we are checking for relay option presence only, break here
                if (check_type == DHCPV6_CHECK_HAS_RELAY_OPT) {
                    break;
                }
                bool inner_msg_relay = (option_relay_msg[0] >= DHCPV6_MESSAGE_TYPE_RELAY_FORW);
                if (check_type == DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY && inner_msg_relay == false) {
                    syslog_debug(LOG_INFO, "check_dhcpv6_message_type: inner dhcpv6 message not relay, skip %s check, context interface %s",
                                 get_check_type_desc_v6((dhcpv6_msg_check_type_t)DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY), context->intf);
                    break;
                }
                if (check_type == DHCPV6_CHECK_LINK_ADDR_INNER_MSG_NOT_RELAY && inner_msg_relay == true) {
                    syslog_debug(LOG_INFO, "check_dhcpv6_message_type: inner dhcpv6 message relay, skip %s check, context interface %s",
                                 get_check_type_desc_v6((dhcpv6_msg_check_type_t)DHCPV6_CHECK_LINK_ADDR_INNER_MSG_NOT_RELAY), context->intf);
                    break;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: %s is true and inner dhcpv6 message %srelay, fallthrough to %s, context interface %s",
                             get_check_type_desc_v6(DHCPV6_CHECK_HAS_RELAY_OPT), inner_msg_relay ? "" : "not ", get_check_type_desc_v6(DHCPV6_CHECK_LINK_ADDR), context->intf);
            }
            case DHCPV6_CHECK_LINK_ADDR:
            case DHCPV6_CHECK_PEER_ADDR: {
                std::vector<const in6_addr *> *ips = (std::vector<const in6_addr *> *)(*profile)[check_type];
                bool is_peer_addr = (check_type == DHCPV6_CHECK_PEER_ADDR);
                const uint8_t *link_or_peer_addr = is_peer_addr ? dhcp6hdr + 18 : dhcp6hdr + 2;
                if (!contains_pointer(*ips, (const in6_addr *)link_or_peer_addr)) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: %s address %s not in expected %s, context interface %s, drop",
                                 is_peer_addr ? "peer" : "link",
                                 generate_addr_string(link_or_peer_addr, sizeof(in6_addr)).c_str(),
                                 generate_vector_string(*ips, [](const in6_addr *addr) { return generate_addr_string((const uint8_t *)addr, sizeof(in6_addr)); }).c_str(),
                                 context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: %s address %s in expected %s, context interface %s",
                             is_peer_addr ? "peer" : "link",
                             generate_addr_string(link_or_peer_addr, sizeof(in6_addr)).c_str(),
                             generate_vector_string(*ips, [](const in6_addr *addr) { return generate_addr_string((const uint8_t *)addr, sizeof(in6_addr)); }).c_str(),
                             context->intf);
                break;
            }
            case DHCPV6_CHECK_INTERFACE_ID: {
                const uint8_t *option_intf_id = find_dhcpv6_option(OPTION_DHCPV6_INTERFACE_ID, dhcp6_options, dhcp6_options_sz);
                // interface id is optional, have to check existence first
                if (option_intf_id == NULL) {
                    syslog_debug(LOG_INFO, "check_dhcpv6_message_type: interface id option not found (optional) in dhcpv6 options, context interface %s",
                                 context->intf);
                    break;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: interface id option found in dhcpv6 options, context interface %s", context->intf);
                uint16_t option_len = ntohs(*(uint16_t *)(option_intf_id - 2));
                if (option_len != sizeof(in6_addr)) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: interface id option length %d not equal to %zu, context interface %s, drop",
                                 option_len, sizeof(in6_addr), context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: interface id option length %d, context interface %s", option_len, context->intf);
                std::vector<const in6_addr *> *ips = (std::vector<const in6_addr *> *)(*profile)[check_type];
                if (!contains_pointer(*ips, (const in6_addr *)option_intf_id)) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: interface id %s not in expected %s, context interface %s, drop",
                                 generate_addr_string((const uint8_t *)option_intf_id, sizeof(in6_addr)).c_str(),
                                 generate_vector_string(*ips, [](const in6_addr *addr) { return generate_addr_string((const uint8_t *)addr, sizeof(in6_addr)); }).c_str(),
                                 context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type: interface id %s in expected %s, context interface %s",
                             generate_addr_string((const uint8_t *)option_intf_id, sizeof(in6_addr)).c_str(),
                             generate_vector_string(*ips, [](const in6_addr *addr) { return generate_addr_string((const uint8_t *)addr, sizeof(in6_addr)); }).c_str(),
                             context->intf);
                break;
            }
            case DHCPV6_CHECK_HOP_COUNT: {
                uint8_t hop_count = dhcp6hdr[1];
                if (hop_count > DHCPV6_RELAY_MAX_HOP) {
                    syslog_debug(LOG_WARNING, "check_dhcpv6_message_type_rx: dhcpv6 relay hop count %d exceeds max %d, context interface %s, drop",
                                hop_count, DHCPV6_RELAY_MAX_HOP, context->intf);
                    return false;
                }
                syslog_debug(LOG_INFO, "check_dhcpv6_message_type_rx: dhcpv6 relay hop count %d within max %d, context interface %s",
                            hop_count, DHCPV6_RELAY_MAX_HOP, context->intf);
                break;
            }
            default: {
                syslog_debug(LOG_WARNING, "check_dhcpv6_message_type: unknown dhcpv6 check type %d, context interface %s, drop", i, context->intf);
                return false;
            }
        }
    }

    syslog_debug(LOG_INFO, "check_dhcpv6_message_type: dhcpv6 message passed all checks, context interface %s", context->intf);

    return true;
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
    return dual_tor_mode && context->intf_type == DHCP_DEVICE_INTF_TYPE_DOWNLINK && (ifname == context->intf || intf_is_standby(ifname));
}

/**
 * @code should_dup_rx_packet(intf, context);
 * @brief duplicate rx packet when intf is different from context interface and not standby physical interface
 * @return boolean
 */
static bool should_dup_rx_packet(const std::string &ifname, const dhcp_device_context_t *context)
{
    return dual_tor_mode && context->intf_type == DHCP_DEVICE_INTF_TYPE_DOWNLINK && ifname != context->intf && !intf_is_standby(ifname);
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
    // it was misunderstood by previous implementation as only the payload length
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

void packet_handler(int sock, const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz)
{
    sock_info_t &sock_info = sock_mgr_get_sock_info(sock);

    syslog_debug(LOG_INFO, "packet_handler %s: handle packet on interface %s, context %s, buffer size %zd", sock_info.name, ifname.c_str(), context->intf, buffer_sz);
    
    // handler will be invoked for physical interface and context interface, so both counters will be updated
    // For single tor and dualtor uplink, no special care is needed
    // For dualtor, rx packets come from downlink standby interfaces will be dropped, hence directly
    // to prevent mis-count, on dualtor downlink
    //   - Ignore packet captured in context interface and standby physical interface
    //   - When capture packet in non-standby physical interface, update context interface and physical
    //     interface count together
    if (sock_info.is_rx && should_ignore_rx_packet(ifname, context)) {
        syslog_debug(LOG_INFO, "packet_handler %s: ignore packet on interface %s, context %s, because is dual tor downlink standby interface",
                     sock_info.name, ifname.c_str(), context->intf);
        return;
    }

    bool dup_to_context = sock_info.is_rx && should_dup_rx_packet(ifname, context);
    syslog_debug(LOG_INFO, "packet_handler %s: duplicate packet from %s to context interface %s: %s",
                 sock_info.name, ifname.c_str(), context->intf, dup_to_context ? "yes" : "no");

    /**
     * The MTU was not understood correctly by earlier DHCP implementations,
     * which treats this MTU as limitation on dhcp packets only.
     * DHCP/v6 will gave a minimum MTU of 576/1280 to conform to IPv4/IPv6 minimum MTU requirements.
     * It is a configuration given to link layer, which includes ethernet header.
     * Also packet size going over the minimum MTU isn't some kind of an error on it's own,
     * because the actual MTU might be well over it. In the previous implementation,
     * this check was only applied to rx packets, which doesn't actually make sense because
     * if packet size goes over mtu, it wouldn't be able to reach us in the first place.
     * So when we received a packet larger than minimum MTU, it means that our current
     * MTU is larger than minimum MTU, and that potentially, it might cause issue when the packet
     * goes to other devices with minimum MTU only. So really it serves as a warning.
     * It would actually make more sense to apply to tx packets, as a warning for user,
     * that we might be having too many hops that could potentially result in overly large packet
     * causing fragmentation or drop along the way.
     * We would also have to move the location of this check from after ip and udp check to before them,
     * because this check is a link layer check that precedes ip and udp layer.
     */
    if (buffer_sz > DHCP_MTU_MIN) {
        syslog_debug(LOG_WARNING, "packet_handler %s: buffer_sz %zd exceeds expectation, interface %s, context %s",
                     sock_info.name, buffer_sz, ifname.c_str(), context->intf);
        increase_cache_counter(ifname, context, sock, DHCP_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "packet_handler %s: buffer_sz check passed, buffer_sz %zd, interface %s, context %s",
                 sock_info.name, buffer_sz, ifname.c_str(), context->intf);

    // first do ip sanity check, checksum only for rx packets because of tx offload
    uint8_t *buffer = sock_info.buffer;
    struct iphdr *iphdr = (struct iphdr* )(buffer + IP_START_OFFSET);
    if (!ip_sanity_check(ifname, iphdr, buffer_sz, sock_info.is_rx)) {
        syslog_debug(LOG_WARNING, "packet_handler %s: packet is not valid ip packet, interface %s, context %s, drop",
                     sock_info.name, ifname.c_str(), context->intf);
        syslog_debug(LOG_WARNING, "packet_handler %s: %s", sock_info.name, generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, sock, DHCP_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iphdr->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iphdr->daddr, dst_ip, INET_ADDRSTRLEN);
    syslog_debug(LOG_INFO, "packet_handler %s: ip sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);

    // then do udp sanity check, checksum only for rx packets because of tx offload
    struct udphdr *udphdr = (struct udphdr*) (buffer + UDP_START_OFFSET);
    if (!udp_sanity_check(ifname, udphdr, buffer, buffer_sz, false, sock_info.is_rx)) {
        syslog_debug(LOG_WARNING, "packet_handler %s: packet is not valid udp packet, interface %s, context %s, src ip %s, dst ip %s, silent drop",
                     sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);
        syslog_debug(LOG_WARNING, "packet_handler %s: %s", sock_info.name, generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, sock, DHCP_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "packet_handler %s: udp sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);

    // when magic cookie doesnt match, it can either be bootp msg or malformed
    uint32_t magic_cookie = ntohl(*((uint32_t *)(buffer + DHCP_MAGIC_COOKIE_OFFSET)));
    if (magic_cookie != DHCP_MAGIC_COOKIE) {
        syslog_debug(LOG_WARNING, "packet_handler %s: magic cookie mismatch, interface %s, context %s, src ip %s, dst ip %s, magic cookie in packet: 0x%X",
                     sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip, magic_cookie);
        increase_cache_counter(ifname, context, sock, DHCP_MESSAGE_TYPE_BOOTP, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "packet_handler %s: magic cookie check passed, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);

    // extract dhcp options size
    // potential dhcp_options_sz can be calculated from udp len - udp hdr len and buffer_sz - all headers, and we pick the smaller
    ssize_t dhcp_sz = ntohs(udphdr->len) - sizeof(struct udphdr) < buffer_sz - DHCP_START_OFFSET ?
                      ntohs(udphdr->len) - sizeof(struct udphdr) : buffer_sz - DHCP_START_OFFSET;
    ssize_t dhcp_options_sz = dhcp_sz - DHCP_HEADER_SIZE;

    // finally look for dhcp option 53
    const uint8_t *dhcp_option_53_ptr;
    if ((dhcp_option_53_ptr = find_dhcp_option_53(buffer + DHCP_OPTIONS_START_OFFSET, dhcp_options_sz)) == NULL) {
        syslog_debug(LOG_WARNING, "packet_handler %s: cannot find option 53 value in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, sock, DHCP_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    dhcp_message_type_t dhcp_option_53 = (dhcp_message_type_t)*dhcp_option_53_ptr;
    syslog_debug(LOG_INFO, "packet_handler %s: found option 53 value %d in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);

    // validate option 53 value
    if (dhcp_option_53 == 0 || dhcp_option_53 > DHCP_MESSAGE_TYPE_INFORM) {
        syslog_debug(LOG_WARNING, "packet_handler %s: unknown option 53 value %d in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, sock, DHCP_MESSAGE_TYPE_UNKNOWN, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "packet_handler %s: option 53 value %d valid, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);

    // perform dhcp option 53 specific sanity check against profile
    if (check_dhcp_option_53(sock_info.is_rx ? (*dhcp_check_profile_ptr_rx)[dhcp_option_53] : (*dhcp_check_profile_ptr_tx)[dhcp_option_53], context, iphdr, buffer)) {
        syslog_debug(LOG_INFO, "packet_handler %s: option 53 value %d check passed, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, sock, dhcp_option_53, dup_to_context);
        return;
    } else {
        syslog_debug(LOG_WARNING, "packet_handler %s: option 53 value %d check failed, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, dhcp_option_53, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, sock, DHCP_MESSAGE_TYPE_DROPPED, dup_to_context);
        return;
    }
}

void packet_handler_v6(int sock, const std::string &ifname, const dhcp_device_context_t *context, ssize_t buffer_sz)
{
    sock_info_t &sock_info = sock_mgr_get_sock_info(sock);

    syslog_debug(LOG_INFO, "packet_handler_v6 %s: handle packet on interface %s, context %s, buffer size %zd", sock_info.name, ifname.c_str(), context->intf, buffer_sz);

    //similar to ipv4 packet handler, need to ignore rx packets on dualtor downlink standby interfaces
    if (sock_info.is_rx && should_ignore_rx_packet(ifname, context)) {
        syslog_debug(LOG_INFO, "packet_handler_v6 %s: ignore packet on interface %s, context %s, because is dual tor downlink standby interface",
                     sock_info.name, ifname.c_str(), context->intf);
        return;
    }

    bool dup_to_context = sock_info.is_rx && should_dup_rx_packet(ifname, context);
    syslog_debug(LOG_INFO, "packet_handler_v6 %s: duplicate packet from %s to context interface %s: %s",
                 sock_info.name, ifname.c_str(), context->intf, dup_to_context ? "yes" : "no");

    // similar to ipv4 packet handler, check buffer size against dhcpv6 minimum mtu first
    if (buffer_sz > DHCPV6_MTU_MIN) {
        syslog_debug(LOG_WARNING, "packet_handler_v6 %s: buffer_sz %zd exceeds expectation, interface %s, context %s",
                     sock_info.name, buffer_sz, ifname.c_str(), context->intf);
        increase_cache_counter(ifname, context, sock, DHCPV6_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "packet_handler_v6 %s: buffer_sz check passed, buffer_sz %zd, interface %s, context %s",
                 sock_info.name, buffer_sz, ifname.c_str(), context->intf);

    // first do ipv6 sanity check and get udp header
    uint8_t *buffer = sock_info.buffer;
    struct udphdr *udphdr;
    if ((udphdr = ipv6_sanity_check(ifname, buffer, buffer_sz)) == NULL) {
        syslog_debug(LOG_WARNING, "packet_handler_v6 %s: packet is not valid ipv6 packet with udp header, interface %s, context %s, silent drop",
                     sock_info.name, ifname.c_str(), context->intf);
        syslog_debug(LOG_WARNING, "packet_handler_v6 %s: %s", sock_info.name, generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, sock, DHCPV6_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(buffer + IP_START_OFFSET);
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6hdr->ip6_src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, &ip6hdr->ip6_dst, dst_ip, sizeof(dst_ip));
    syslog_debug(LOG_INFO, "packet_handler_v6 %s: ipv6 sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);
                 
    // then do udp sanity check, checksum only for rx packets because of tx offload
    if (!udp_sanity_check(ifname, udphdr, buffer, buffer_sz, true, sock_info.is_rx)) {
        syslog_debug(LOG_WARNING, "packet_handler_v6 %s: packet is not valid udp packet, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);
        syslog_debug(LOG_WARNING, "packet_handler_v6 %s: %s", sock_info.name, generate_addr_string(buffer, buffer_sz).c_str());
        increase_cache_counter(ifname, context, sock, DHCPV6_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "packet_handler_v6 %s: udp sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);

    // extract dhcpv6 header and validate message type
    uint8_t *dhcp6hdr = (uint8_t *)udphdr + sizeof(struct udphdr);
    dhcpv6_message_type_t msg_type = (dhcpv6_message_type_t)*dhcp6hdr;
    if (msg_type == 0 || msg_type > DHCPV6_MESSAGE_TYPE_RELAY_REPL) {
        syslog_debug(LOG_WARNING, "packet_handler_v6 %s: unknown dhcpv6 message type value %d in dhcp packet, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, sock, DHCPV6_MESSAGE_TYPE_UNKNOWN, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "packet_handler_v6 %s: dhcpv6 message type %d valid, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);

    // extract dhcpv6 options
    uint8_t *dhcp6_options = dhcp6hdr + (msg_type < DHCPV6_MESSAGE_TYPE_RELAY_FORW ? DHCPV6_HEADER_SIZE : DHCPV6_RELAY_HEADER_SIZE);
    ssize_t dhcp6_sz = ntohs(udphdr->len) - sizeof(struct udphdr) < buffer_sz - (dhcp6hdr - buffer) ?
                       ntohs(udphdr->len) - sizeof(struct udphdr) : buffer_sz - (dhcp6hdr - buffer);
    ssize_t dhcp6_options_sz = dhcp6_sz - (dhcp6_options - dhcp6hdr);

    // perform dhcpv6 specific sanity check
    if (!dhcpv6_sanity_check(ifname, dhcp6hdr, dhcp6_options, dhcp6_options_sz)) {
        syslog_debug(LOG_WARNING, "packet_handler_v6 %s: dhcpv6 packet sanity check failed, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, sock, DHCPV6_MESSAGE_TYPE_MALFORMED, dup_to_context);
        return;
    }
    syslog_debug(LOG_INFO, "packet_handler_v6 %s: dhcpv6 sanity check passed, interface %s, context %s, src ip %s, dst ip %s",
                 sock_info.name, ifname.c_str(), context->intf, src_ip, dst_ip);

    if (check_dhcpv6_message_type(sock_info.is_rx ? (*dhcpv6_check_profile_ptr_rx)[msg_type] : (*dhcpv6_check_profile_ptr_tx)[msg_type],
                                  context, ip6hdr, dhcp6hdr, dhcp6_options, dhcp6_options_sz)) {
        syslog_debug(LOG_INFO, "packet_handler_v6 %s: dhcpv6 message type %d check passed, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, sock, msg_type, dup_to_context);
        return;
    } else {
        syslog_debug(LOG_WARNING, "packet_handler_v6 %s: dhcpv6 message type %d check failed, interface %s, context %s, src ip %s, dst ip %s",
                     sock_info.name, msg_type, ifname.c_str(), context->intf, src_ip, dst_ip);
        increase_cache_counter(ifname, context, sock, DHCPV6_MESSAGE_TYPE_DROPPED, dup_to_context);
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
            ((packet_handler_t)sock_info.packet_handler)(fd, ifname, context, buffer_sz);
            debug_mask = true;
        }
    }
}