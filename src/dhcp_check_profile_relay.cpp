/**
 * @file dhcp_check_profile_relay.cpp
 * 
 * DHCP/v6 check profile for dhcp relay, used in T0/M0/Mx devices
 * 
 * For our T0/M0 topo, host is the first relay between clients and servers. For DHCP, we expect forward packets going in on downlink interface
 * and reply packets going out on downlink interface. For DHCPv6, we expect forward packets going in and reply packets going out on downlink interface,
 * and relay forward packets going out and relay reply packets going in on uplink interface.
 * The difference with DHCPv4 and v6 is that, first, DHCPv6 has relay and non-relay packets. Second, with DHCPv6, it is easy to tell that downstream
 * is client or relay because they would have different msg type (non-relay and relay), and thus handled by different check profiles. However
 * with DHCPv4, client and relay send packets of the same msg type, so we can't just mix them together. We only expect downstream client on T0/M0 topo.
 * With other roles, we might have relay downstream as well.
 * Moreover, for DHCP, T0 is special becauses it's the first relay, and the only relay that server is going to see (relay after the first relay does
 * not change giaddr).
 * 
 * For Mx topo, DHCPv6 is the same as M0, but Mx host is itself the DHCP server. So we expect different check profile for Mx. There should be nothing
 * going in and out of uplink interface. All packets should go in and out of downlink interface.
 */

#include <vector>

#include "dhcp_check_profile.h"

#include "dhcp_devman.h"

/******************************************
 *   DHCP First Relay Profile (T0/M0)     *
 ******************************************/

// DHCP messages sent by client
// In case of host being the first relay (T0/M0), when packets were sent from client, giaddr will always be 0, because how would client know.
// Client communicates with relay through broadcast only. Client does unicast to server when it knows server address.
// Previous implementation also considered packet giaddr to be giaddr of this relay, which is not possible.
// Downstream is either client, which give 0 giaddr, or relay, which gives giaddr of its own ip (or ip of even previous relay),
// either case the giaddr is not going to be the ip of this relay. Also we further restricts this profile to first relay (T0/M0) only
// where downstream is definitely client only.
static dhcp_msg_check_profile_t rx_first_relay_forward = {
    {DHCP_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_DOWNLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCP_CHECK_DST_IP, (const void *)(new std::vector<const in_addr *>{&broadcast_ip})},
    {DHCP_CHECK_GIADDR, (const void *)(new std::vector<const in_addr *>{&zero_ip})},
};

// DHCP messages sent by server or relay
// When server receives a request, it replies to the giaddr address specified in the request packet, which is the first relay.
// In case of a first relay (T0/M0), this is the last relay before reaching client, so giaddr and dst_ip must be of this relay.
static dhcp_msg_check_profile_t rx_first_relay_reply = {
    {DHCP_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_UPLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCP_CHECK_DST_IP, (const void *)(new std::vector<const in_addr *>{&giaddr_ip})},
    {DHCP_CHECK_GIADDR, (const void *)(new std::vector<const in_addr *>{&giaddr_ip})},
};

// forward packets going in on downlink interface, reply packets going in on uplink interface
dhcp_check_profile_t dhcp_check_profile_first_relay_rx = {
    {DHCP_MESSAGE_TYPE_DISCOVER, &rx_first_relay_forward},
    {DHCP_MESSAGE_TYPE_OFFER, &rx_first_relay_reply},
    {DHCP_MESSAGE_TYPE_REQUEST, &rx_first_relay_forward},
    {DHCP_MESSAGE_TYPE_DECLINE, &rx_first_relay_forward},
    {DHCP_MESSAGE_TYPE_ACK, &rx_first_relay_reply},
    {DHCP_MESSAGE_TYPE_NAK, &rx_first_relay_reply},
    {DHCP_MESSAGE_TYPE_RELEASE, &rx_first_relay_forward},
    {DHCP_MESSAGE_TYPE_INFORM, &rx_first_relay_forward},
};

// DHCP messages sent to client
// Relay sends reply packets to client with broadcast ip, and giaddr will not be unset so it remains giaddr of the first relay.
static dhcp_msg_check_profile_t tx_first_relay_reply = {
    {DHCP_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_DOWNLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCP_CHECK_SRC_IP, (const void *)(new std::vector<const in_addr *>{&giaddr_ip})},
    {DHCP_CHECK_DST_IP, (const void *)(new std::vector<const in_addr *>{&broadcast_ip})},
    {DHCP_CHECK_GIADDR, (const void *)(new std::vector<const in_addr *>{&giaddr_ip})},
};

// DHCP messages sent to server or relay
// When relay receive a forward packet from client, it will set giaddr to its own address before forwarding to server.
// For subsequent relays, packet giaddr will remain unchanged. We are the first relay (T0/M0), so giaddr must be of this relay.
// Relay does not care if it sends to a server or a relay
static dhcp_msg_check_profile_t tx_first_relay_forward = {
    {DHCP_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_UPLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCP_CHECK_SRC_IP, (const void *)(new std::vector<const in_addr *>{&giaddr_ip})},
    {DHCP_CHECK_GIADDR, (const void *)(new std::vector<const in_addr *>{&giaddr_ip})},
};

// reply packets going out on downlink interface, forward packets going out on uplink interface
dhcp_check_profile_t dhcp_check_profile_first_relay_tx = {
    {DHCP_MESSAGE_TYPE_DISCOVER, &tx_first_relay_forward},
    {DHCP_MESSAGE_TYPE_OFFER, &tx_first_relay_reply},
    {DHCP_MESSAGE_TYPE_REQUEST, &tx_first_relay_forward},
    {DHCP_MESSAGE_TYPE_DECLINE, &tx_first_relay_forward},
    {DHCP_MESSAGE_TYPE_ACK, &tx_first_relay_reply},
    {DHCP_MESSAGE_TYPE_NAK, &tx_first_relay_reply},
    {DHCP_MESSAGE_TYPE_RELEASE, &tx_first_relay_forward},
    {DHCP_MESSAGE_TYPE_INFORM, &tx_first_relay_forward},
};

/******************************************
 *   DHCP Server Profile (Mx)             *
 ******************************************/

// DHCP messages sent by client
// In case of host being the server (Mx) with no relay in between, when packets were sent from client, giaddr will always be 0 at first,
// because client wouldn't know. However after clients received reply from server, clients will set giaddr to server address for subsequent requests.
// More specifically, from client to server, DISCOVER/REQUEST can only be broadcast, DECLINE/RELEASE/INFORM can only be unicast to server address.
// From server to client, OFEER/ACK can be either and NAK can only be broadcast. For now we accept dst ip to be either for less trouble.
// For Mx downstream is client, which give 0 giaddr.
static dhcp_msg_check_profile_t rx_server_forward = {
    {DHCP_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_DOWNLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCP_CHECK_DST_IP, (const void *)(new std::vector<const in_addr *>{&broadcast_ip, &giaddr_ip})},
    {DHCP_CHECK_GIADDR, (const void *)(new std::vector<const in_addr *>{&zero_ip})},
};

// forward packets going in on downlink interface, no in and out on uplink
dhcp_check_profile_t dhcp_check_profile_server_rx = {
    {DHCP_MESSAGE_TYPE_DISCOVER, &rx_server_forward},
    {DHCP_MESSAGE_TYPE_OFFER, NULL},
    {DHCP_MESSAGE_TYPE_REQUEST, &rx_server_forward},
    {DHCP_MESSAGE_TYPE_DECLINE, &rx_server_forward},
    {DHCP_MESSAGE_TYPE_ACK, NULL},
    {DHCP_MESSAGE_TYPE_NAK, NULL},
    {DHCP_MESSAGE_TYPE_RELEASE, &rx_server_forward},
    {DHCP_MESSAGE_TYPE_INFORM, &rx_server_forward},
};

// DHCP messages sent to client
// Server sends reply packets to client with broadcast or unicast, but we don't know the ip of the client, so we skip checking it,
// and giaddr will be zero because there is no relay involved. The variable name is still giaddr because it was originally for relay
// only, but the giaddr really means host ip that sends the packet.
static dhcp_msg_check_profile_t tx_server_reply = {
    {DHCP_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_DOWNLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCP_CHECK_SRC_IP, (const void *)(new std::vector<const in_addr *>{&giaddr_ip})},
    {DHCP_CHECK_GIADDR, (const void *)(new std::vector<const in_addr *>{&zero_ip})},
};

// reply packets going out on downlink interface, no in and out on uplink
dhcp_check_profile_t dhcp_check_profile_server_tx = {
    {DHCP_MESSAGE_TYPE_DISCOVER, NULL},
    {DHCP_MESSAGE_TYPE_OFFER, &tx_server_reply},
    {DHCP_MESSAGE_TYPE_REQUEST, NULL},
    {DHCP_MESSAGE_TYPE_DECLINE, NULL},
    {DHCP_MESSAGE_TYPE_ACK, &tx_server_reply},
    {DHCP_MESSAGE_TYPE_NAK, &tx_server_reply},
    {DHCP_MESSAGE_TYPE_RELEASE, NULL},
    {DHCP_MESSAGE_TYPE_INFORM, NULL},
};

/******************************************
 *   DHCPv6 Relay Profile (T0/M0/Mx)      *
 ******************************************/

// DHCPv6 messages sent by client
// Solicit, Rebind, and Confirm has multicast addr as dst ip for sure, but the others might not, it could be unicast to relay address
// client learns relay address from non-relay reply packets (relay to client), refer to tx_non_relay_reply, src_ip is lla of relay
// so client learns lla of relay as relay address, and uses lla of relay as dst_ip when sending non-relay forward to relay next time
static dhcpv6_msg_check_profile_t rx_relay_non_relay_forward = {
    {DHCPV6_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_DOWNLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCPV6_CHECK_DST_IP, (const void *)(new std::vector<const in6_addr *>{&dhcpv6_multicast_ipv6, &vlan_ipv6_lla})},
    {DHCPV6_CHECK_HAS_RELAY_OPT, (const void *)(new bool(false))},
};

// DHCPv6 messages sent by relay
// relay forward packets sent by relay (relay to relay, receiving) should be the same as the relay forward packets sent to relay (relay to relay, sending)
// relay relay a forward packet, whether it be relay forward or non-relay forward, to preconfigured server ip,
// could be either the gua or lla of next relay, all we know it's definitely not going to be multicast address
// TODO: 1. verify whether relay ip is configured to be gua or lla
static dhcpv6_msg_check_profile_t rx_relay_relay_forward = {
    {DHCPV6_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_DOWNLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCPV6_CHECK_DST_IP, (const void *)(new std::vector<const in6_addr *>{&vlan_ipv6_gua, &vlan_ipv6_lla})},
    {DHCPV6_CHECK_HOP_COUNT, (const void *)(new bool(true))},
    {DHCPV6_CHECK_HAS_RELAY_OPT, (const void *)(new bool(true))},
};

// DHCPv6 messages sent by server or relay
// relay reply packets sent by server or relay (server/relay to relay) should have the same header as the relay forward packets sent to server (relay to server/relay)
// so it will share similar check to tx_relay_forward
static dhcpv6_msg_check_profile_t rx_relay_relay_reply = {
    {DHCPV6_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_UPLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCPV6_CHECK_DST_IP, (const void *)(new std::vector<const in6_addr *>{&giaddr_ipv6_gua})},
    {DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY, (const void *)(new std::vector<const in6_addr *>{&zero_ipv6})},
    {DHCPV6_CHECK_LINK_ADDR_INNER_MSG_NOT_RELAY, (const void *)(new std::vector<const in6_addr *>{&vlan_ipv6_gua, &vlan_ipv6_lla})},
    {DHCPV6_CHECK_INTERFACE_ID, (const void *)(new std::vector<const in6_addr *>{&vlan_ipv6_gua, &vlan_ipv6_lla})},
    {DHCPV6_CHECK_HAS_RELAY_OPT, (const void *)(new bool(true))},
};

// forward packets going in on downlink interface, relay reply packets going in on uplink interface
// non-relay reply packets should not exist
dhcpv6_check_profile_t dhcpv6_check_profile_relay_rx = {
    {DHCPV6_MESSAGE_TYPE_SOLICIT, &rx_relay_non_relay_forward},
    {DHCPV6_MESSAGE_TYPE_ADVERTISE, NULL},
    {DHCPV6_MESSAGE_TYPE_REQUEST, &rx_relay_non_relay_forward},
    {DHCPV6_MESSAGE_TYPE_CONFIRM, &rx_relay_non_relay_forward},
    {DHCPV6_MESSAGE_TYPE_RENEW, &rx_relay_non_relay_forward},
    {DHCPV6_MESSAGE_TYPE_REBIND, &rx_relay_non_relay_forward},
    {DHCPV6_MESSAGE_TYPE_REPLY, NULL},
    {DHCPV6_MESSAGE_TYPE_RELEASE, &rx_relay_non_relay_forward},
    {DHCPV6_MESSAGE_TYPE_DECLINE, &rx_relay_non_relay_forward},
    {DHCPV6_MESSAGE_TYPE_RECONFIGURE, NULL},
    {DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST, &rx_relay_non_relay_forward},
    {DHCPV6_MESSAGE_TYPE_RELAY_FORW, &rx_relay_relay_forward},
    {DHCPV6_MESSAGE_TYPE_RELAY_REPL, &rx_relay_relay_reply},
};

// DHCPv6 messages sent to client or relay
// can come from 1 place in dhcp_relay
// 1. from relay_relay_reply, the packet (relay to client) was sent from either gua (when previous relay reply packet (server/relay to relay)
//    link_address is 0 and peer_address is not link local) or lla sock (otherwise), using gua and lla of relay as src_ip respectively
//    since relay reply packets (server/relay to relay) share the same header as the previous relay forward packet (relay to server/relay),
//    we can refer to tx_relay_forward, the packet comes from either relay_client (when previous packet is non-relay forward (client to relay))
//    or relay_relay_forward (when previous packet is relay forward (relay to relay))
//    since this is non-relay reply (relay to client), its previous packet was non-relay forward (client to relay), it will be forwarded by relay_client,
//    where link_address = config->link_address, not 0, so we trace back, and non-relay reply packet (relay to client) can only be lla
//    to summarize, non-relay forward (client to relay) reaches relay, relay wraps it in relay forward to server/relay with relay_client,
//    where link_address = config->link_address (nonzero), server/relay sends back relay reply to relay, again with link_address nonzero,
//    relay unwraps it and sends non-relay reply to client with relay_relay_reply, where link_address nonzero means from lla sock, src_ip is lla of relay
static dhcpv6_msg_check_profile_t tx_relay_non_relay_reply = {
    {DHCPV6_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_DOWNLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCPV6_CHECK_SRC_IP, (const void *)(new std::vector<const in6_addr *>{&vlan_ipv6_lla})},
    {DHCPV6_CHECK_HAS_RELAY_OPT, (const void *)(new bool(false))},
};

// DHCPv6 messages sent to server
// can come from 2 places in dhcp_relay
// 1. from relay_client, peer_address = ip_src (client ip), link_address = config->link_address, interface_id = config->link_address
// 2. from relay_relay_forward, peer_address = ip_src (relay ip), link_address = 0, interface_id = config->link_address
// where config->link_address is almost always the gua of vlan (lla only when gua does not exist)
// in both case, the packet was sent from the gua sock (single tor) or lo sock (dual tor), so src_ip is either vlan_gua (single tor) or loopback_gua (dual tor)
static dhcpv6_msg_check_profile_t tx_relay_relay_forward = {
    {DHCPV6_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_UPLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCPV6_CHECK_SRC_IP, (const void *)(new std::vector<const in6_addr *>{&giaddr_ipv6_gua})},
    {DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY, (const void *)(new std::vector<const in6_addr *>{&zero_ipv6})},
    {DHCPV6_CHECK_LINK_ADDR_INNER_MSG_NOT_RELAY, (const void *)(new std::vector<const in6_addr *>{&vlan_ipv6_gua, &vlan_ipv6_lla})},
    {DHCPV6_CHECK_INTERFACE_ID, (const void *)(new std::vector<const in6_addr *>{&vlan_ipv6_gua, &vlan_ipv6_lla})},
    {DHCPV6_CHECK_HAS_RELAY_OPT, (const void *)(new bool(true))},
};

// DHCPv6 messages sent to relay
// TODO: 1. is dhcpmon supposed to run on server?
// can come from 1 place in dhcp_relay
// 1. from relay_relay_reply, so its similar to tx_non_relay_reply but different in link_address
//    since this is relay reply (relay to relay), its previous packet was relay forward (relay to relay), it will be forwarded by relay_relay_forward,
//    where link_address = 0, and whether src_ip is gua or lla sock depends on whether peer_address is link local
//    since relay reply packet (relay to relay) share the same header as the previous relay forward packet (relay to relay),
//    we can refer to tx_relay_forward, where peer_address = ip_src (relay ip), so whether src_ip is gua or lla sock depends on whether relay ip is link local
// TODO: 1. verify whether relay ip is configured to be gua or lla
static dhcpv6_msg_check_profile_t tx_relay_relay_reply = {
    {DHCPV6_CHECK_INTF_TYPE, (const void *)(new std::vector<dhcp_device_intf_t>{DHCP_DEVICE_INTF_TYPE_DOWNLINK, DHCP_DEVICE_INTF_TYPE_MGMT})},
    {DHCPV6_CHECK_SRC_IP, (const void *)(new std::vector<const in6_addr *>{&vlan_ipv6_gua, &vlan_ipv6_lla})},
    {DHCPV6_CHECK_HAS_RELAY_OPT, (const void *)(new bool(true))},
};

// reply packets going out on downlink interface, relay forward packets going out on uplink interface
// non-relay forward packets should not exist
dhcpv6_check_profile_t dhcpv6_check_profile_relay_tx = {
    {DHCPV6_MESSAGE_TYPE_SOLICIT, NULL},
    {DHCPV6_MESSAGE_TYPE_ADVERTISE, &tx_relay_non_relay_reply},
    {DHCPV6_MESSAGE_TYPE_REQUEST, NULL},
    {DHCPV6_MESSAGE_TYPE_CONFIRM, NULL},
    {DHCPV6_MESSAGE_TYPE_RENEW, NULL},
    {DHCPV6_MESSAGE_TYPE_REBIND, NULL},
    {DHCPV6_MESSAGE_TYPE_REPLY, &tx_relay_non_relay_reply},
    {DHCPV6_MESSAGE_TYPE_RELEASE, NULL},
    {DHCPV6_MESSAGE_TYPE_DECLINE, NULL},
    {DHCPV6_MESSAGE_TYPE_RECONFIGURE, &tx_relay_non_relay_reply},
    {DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST, NULL},
    {DHCPV6_MESSAGE_TYPE_RELAY_FORW, &tx_relay_relay_forward},
    {DHCPV6_MESSAGE_TYPE_RELAY_REPL, &tx_relay_relay_reply},
};