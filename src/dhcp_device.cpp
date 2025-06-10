/**
 * @file dhcp_device.c
 *
 *  device (interface) module
 */

#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <inttypes.h>
#include <libexplain/ioctl.h>
#include <linux/filter.h>
#include <netpacket/packet.h>
#include "select.h"

#include "dhcp_devman.h"
#include "dhcp_device.h"
#include "event_mgr.h"

/** Counter print width */
#define DHCP_COUNTER_WIDTH  9

/** Start of Ether header of a captured frame */
#define ETHER_START_OFFSET  0
/** Start of IP header of a captured frame */
#define IP_START_OFFSET (ETHER_START_OFFSET + ETHER_HDR_LEN)
/** Start of UDP header of a captured frame */
#define UDP_START_OFFSET (IP_START_OFFSET + sizeof(struct ip))
/** Start of DHCP header of a captured frame */
#define DHCP_START_OFFSET (UDP_START_OFFSET + sizeof(struct udphdr))
/** Start of DHCP Options segment of a captured frame */
#define DHCP_OPTIONS_HEADER_SIZE 240
/** Offset of DHCP GIADDR */
#define DHCP_GIADDR_OFFSET 24
/** Offset of magic cookie */
#define MAGIC_COOKIE_OFFSET 236
/** 32-bit decimal of 99.130.83.99 (indicate DHCP packets), Refer to RFC 2131 */
#define DHCP_MAGIC_COOKIE 1669485411

#define OP_LDHA     (BPF_LD  | BPF_H   | BPF_ABS)   /** bpf ldh Abs */
#define OP_LDHI     (BPF_LD  | BPF_H   | BPF_IND)   /** bpf ldh Ind */
#define OP_LDB      (BPF_LD  | BPF_B   | BPF_ABS)   /** bpf ldb Abs*/
#define OP_JEQ      (BPF_JMP | BPF_JEQ | BPF_K)     /** bpf jeq */
#define OP_JGT      (BPF_JMP | BPF_JGT | BPF_K)     /** bpf jgt */
#define OP_RET      (BPF_RET | BPF_K)               /** bpf ret */
#define OP_JSET     (BPF_JMP | BPF_JSET | BPF_K)    /** bpf jset */
#define OP_LDXB     (BPF_LDX | BPF_B    | BPF_MSH)  /** bpf ldxb */

std::shared_ptr<swss::DBConnector> mConfigDbPtr = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
std::shared_ptr<swss::DBConnector> mStateDbPtr = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
std::shared_ptr<swss::DBConnector> mCountersDbPtr = std::make_shared<swss::DBConnector> ("COUNTERS_DB", 0);
std::shared_ptr<swss::Table> mStateDbMuxTablePtr = std::make_shared<swss::Table> (
    mStateDbPtr.get(), "HW_MUX_CABLE_TABLE"
);

/* interface to vlan mapping */
std::unordered_map<std::string, std::string> vlan_map;

/* interface to port-channel mapping */
std::unordered_map<std::string, std::string> portchan_map;

/* interface to mgmt port mapping */
std::unordered_map<std::string, std::string> mgmt_map;

/* RX per-interface counter data */
std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>> rx_counter;

/* TX per-interface counter data */
std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>> tx_counter;

/* db counter name array, message type rage [1, 9] */
std::string db_counter_name[DHCP_MESSAGE_TYPE_COUNT] = {
    "Unknown", "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform", "Bootp"
};

/** Berkeley Packet Filter program for "udp and (port 67 or port 68)".
 * This program is obtained using the following command tcpdump:
 * `tcpdump -dd "outbound and udp and (port 67 or port 68)"`
 */
static struct sock_filter dhcp_outbound_bpf_code[] = {
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0xfffff004}, // (000) ldh      #fffff004
    {.code = OP_JEQ,  .jt = 0,  .jf = 22, .k = 0x00000004}, // (001) jeq      #0x04            jt 0 jf 22
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0x0000000c}, // (002) ldh      [12]
    {.code = OP_JEQ,  .jt = 0,  .jf = 7,  .k = 0x000086dd}, // (003) jeq      #0x86dd          jt 2	jf 9
    {.code = OP_LDB,  .jt = 0,  .jf = 0,  .k = 0x00000014}, // (004) ldb      [20]
    {.code = OP_JEQ,  .jt = 0,  .jf = 18, .k = 0x00000011}, // (005) jeq      #0x11            jt 4	jf 22
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0x00000036}, // (006) ldh      [54]
    {.code = OP_JEQ,  .jt = 15, .jf = 0,  .k = 0x00000043}, // (007) jeq      #0x43            jt 21	jf 6
    {.code = OP_JEQ,  .jt = 14, .jf = 0,  .k = 0x00000044}, // (008) jeq      #0x44            jt 21	jf 7
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0x00000038}, // (009) ldh      [56]
    {.code = OP_JEQ,  .jt = 12, .jf = 11, .k = 0x00000043}, // (010) jeq      #0x43            jt 21	jf 20
    {.code = OP_JEQ,  .jt = 0,  .jf = 12, .k = 0x00000800}, // (011) jeq      #0x800           jt 10	jf 22
    {.code = OP_LDB,  .jt = 0,  .jf = 0,  .k = 0x00000017}, // (012) ldb      [23]
    {.code = OP_JEQ,  .jt = 0,  .jf = 10, .k = 0x00000011}, // (013) jeq      #0x11            jt 12	jf 22
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0x00000014}, // (014) ldh      [20]
    {.code = OP_JSET, .jt = 8,  .jf = 0,  .k = 0x00001fff}, // (015) jset     #0x1fff          jt 22	jf 14
    {.code = OP_LDXB, .jt = 0,  .jf = 0,  .k = 0x0000000e}, // (016) ldxb     4*([14]&0xf)
    {.code = OP_LDHI, .jt = 0,  .jf = 0,  .k = 0x0000000e}, // (017) ldh      [x + 14]
    {.code = OP_JEQ,  .jt = 4,  .jf = 0,  .k = 0x00000043}, // (018) jeq      #0x43            jt 21	jf 17
    {.code = OP_JEQ,  .jt = 3,  .jf = 0,  .k = 0x00000044}, // (019) jeq      #0x44            jt 21	jf 18
    {.code = OP_LDHI, .jt = 0,  .jf = 0,  .k = 0x00000010}, // (020) ldh      [x + 16]
    {.code = OP_JEQ,  .jt = 1,  .jf = 0,  .k = 0x00000043}, // (021) jeq      #0x43            jt 21	jf 20
    {.code = OP_JEQ,  .jt = 0,  .jf = 1,  .k = 0x00000044}, // (022) jeq      #0x44            jt 21	jf 22
    {.code = OP_RET,  .jt = 0,  .jf = 0,  .k = 0x00040000}, // (023) ret      #262144
    {.code = OP_RET,  .jt = 0,  .jf = 0,  .k = 0x00000000}, // (024) ret      #0
};

/** Berkeley Packet Filter program for "udp and (port 67 or port 68)".
 * This program is obtained using the following command tcpdump:
 * `tcpdump -dd "inbound and udp and (port 67 or port 68)"`
 */
static struct sock_filter dhcp_inbound_bpf_code[] = {
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0xfffff004}, // (000) ldh      #fffff004
    {.code = OP_JEQ,  .jt = 22, .jf = 0, .k = 0x00000004},  // (001) jeq      #0x04            jt 22 jf 0
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0x0000000c}, // (002) ldh      [12]
    {.code = OP_JEQ,  .jt = 0,  .jf = 7,  .k = 0x000086dd}, // (003) jeq      #0x86dd          jt 2	jf 9
    {.code = OP_LDB,  .jt = 0,  .jf = 0,  .k = 0x00000014}, // (004) ldb      [20]
    {.code = OP_JEQ,  .jt = 0,  .jf = 18, .k = 0x00000011}, // (005) jeq      #0x11            jt 4	jf 22
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0x00000036}, // (006) ldh      [54]
    {.code = OP_JEQ,  .jt = 15, .jf = 0,  .k = 0x00000043}, // (007) jeq      #0x43            jt 21	jf 6
    {.code = OP_JEQ,  .jt = 14, .jf = 0,  .k = 0x00000044}, // (008) jeq      #0x44            jt 21	jf 7
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0x00000038}, // (009) ldh      [56]
    {.code = OP_JEQ,  .jt = 12, .jf = 11, .k = 0x00000043}, // (010) jeq      #0x43            jt 21	jf 20
    {.code = OP_JEQ,  .jt = 0,  .jf = 12, .k = 0x00000800}, // (011) jeq      #0x800           jt 10	jf 22
    {.code = OP_LDB,  .jt = 0,  .jf = 0,  .k = 0x00000017}, // (012) ldb      [23]
    {.code = OP_JEQ,  .jt = 0,  .jf = 10, .k = 0x00000011}, // (013) jeq      #0x11            jt 12	jf 22
    {.code = OP_LDHA, .jt = 0,  .jf = 0,  .k = 0x00000014}, // (014) ldh      [20]
    {.code = OP_JSET, .jt = 8,  .jf = 0,  .k = 0x00001fff}, // (015) jset     #0x1fff          jt 22	jf 14
    {.code = OP_LDXB, .jt = 0,  .jf = 0,  .k = 0x0000000e}, // (016) ldxb     4*([14]&0xf)
    {.code = OP_LDHI, .jt = 0,  .jf = 0,  .k = 0x0000000e}, // (017) ldh      [x + 14]
    {.code = OP_JEQ,  .jt = 4,  .jf = 0,  .k = 0x00000043}, // (018) jeq      #0x43            jt 21	jf 17
    {.code = OP_JEQ,  .jt = 3,  .jf = 0,  .k = 0x00000044}, // (019) jeq      #0x44            jt 21	jf 18
    {.code = OP_LDHI, .jt = 0,  .jf = 0,  .k = 0x00000010}, // (020) ldh      [x + 16]
    {.code = OP_JEQ,  .jt = 1,  .jf = 0,  .k = 0x00000043}, // (021) jeq      #0x43            jt 21	jf 20
    {.code = OP_JEQ,  .jt = 0,  .jf = 1,  .k = 0x00000044}, // (022) jeq      #0x44            jt 21	jf 22
    {.code = OP_RET,  .jt = 0,  .jf = 0,  .k = 0x00040000}, // (023) ret      #262144
    {.code = OP_RET,  .jt = 0,  .jf = 0,  .k = 0x00000000}, // (024) ret      #0
};

/** Filter program socket struct */
static struct sock_fprog dhcp_outbound_sock_bfp = {
    .len = sizeof(dhcp_outbound_bpf_code) / sizeof(*dhcp_outbound_bpf_code), .filter = dhcp_outbound_bpf_code
};
static struct sock_fprog dhcp_inbound_sock_bfp = {
    .len = sizeof(dhcp_inbound_bpf_code) / sizeof(*dhcp_inbound_bpf_code), .filter = dhcp_inbound_bpf_code
};

static uint8_t *rx_recv_buffer = NULL;
static uint8_t *tx_recv_buffer = NULL;
static uint32_t snap_length;

/** Aggregate device of DHCP interfaces. It contains aggregate counters from
    all interfaces
 */
static dhcp_device_context_t aggregate_dev = {0};

/** Monitored DHCP message type */
static dhcp_message_type_t monitored_msgs[] = {
    DHCP_MESSAGE_TYPE_DISCOVER,
    DHCP_MESSAGE_TYPE_OFFER,
    DHCP_MESSAGE_TYPE_REQUEST,
    DHCP_MESSAGE_TYPE_ACK
};

/** Downstream interface name */
std::string downstream_if_name;

/** update ethernet interface to vlan map
 *  VLAN_MEMBER|Vlan1000|Ethernet48
 */
void update_vlan_mapping(std::shared_ptr<swss::DBConnector> db_conn) {
    auto match_pattern = std::string("VLAN_MEMBER|*");
    auto keys = db_conn->keys(match_pattern);
    std::unordered_set<std::string> vlans;
    for (auto &itr : keys) {
        auto first = itr.find_first_of('|');
        auto second = itr.find_last_of('|');
        auto vlan = itr.substr(first + 1, second - first - 1);
        if (vlan.compare(downstream_if_name) != 0) {
            continue;
        }
        auto interface = itr.substr(second + 1);
        vlan_map[interface] = vlan;
        vlans.insert(vlan);
        syslog(LOG_INFO, "add <%s, %s> into interface vlan map\n", interface.c_str(), vlan.c_str());
        std::string ifname = interface;
        initialize_db_counters(ifname);

        initialize_cache_counter(rx_counter, ifname);
        initialize_cache_counter(tx_counter, ifname);
    }
    for (auto ifname : vlans) {
        initialize_db_counters(ifname);

        initialize_cache_counter(rx_counter, ifname);
        initialize_cache_counter(tx_counter, ifname);
    }
}

/**
 * @code initialize_cache_counter(std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>> &counters, std::string interface_name);
 * @brief Initialize cache counter per interface
 * @param counters         counter data
 * @param interface_name   string value of interface name
 */
void initialize_cache_counter(std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>> &counters, std::string interface_name) {
    auto counter = counters.find(interface_name);
    if (counter != counters.end()) {
        return;
    }

    std::unordered_map<uint8_t, uint64_t> new_counter;
    for (int i = 0; i < DHCP_MESSAGE_TYPE_COUNT; i++) {
        new_counter[i] = 0;
    }

    counters[interface_name] = new_counter;
}

/** update ethernet interface to port-channel map
 *  PORTCHANNEL_MEMBER|PortChannel101|Ethernet112
 */
void update_portchannel_mapping(std::shared_ptr<swss::DBConnector> db_conn) {
    auto match_pattern = std::string("PORTCHANNEL_MEMBER|*");
    auto keys = db_conn->keys(match_pattern);
    std::unordered_set<std::string> portchannels;
    for (auto &itr : keys) {
        auto first = itr.find_first_of('|');
        auto second = itr.find_last_of('|');
        auto portchannel = itr.substr(first + 1, second - first - 1);
        auto interface = itr.substr(second + 1);
        portchan_map[interface] = portchannel;
        portchannels.insert(portchannel);
        syslog(LOG_INFO, "add <%s, %s> into interface port-channel map\n", interface.c_str(), portchannel.c_str());
        std::string ifname = interface;
        initialize_db_counters(ifname);

        initialize_cache_counter(rx_counter, ifname);
        initialize_cache_counter(tx_counter, ifname);
    }
    for (auto ifname : portchannels) {
        initialize_db_counters(ifname);

        initialize_cache_counter(rx_counter, ifname);
        initialize_cache_counter(tx_counter, ifname);
    }
}

/** update interface to mgmt map
 */
void update_mgmt_mapping() {
    auto mgmt = dhcp_devman_get_mgmt_dev();
    if (mgmt) {
        auto name = std::string(mgmt->intf);
        mgmt_map[name] = name;
        initialize_db_counters(name);

        initialize_cache_counter(rx_counter, name);
        initialize_cache_counter(tx_counter, name);
    }
}

/**
 * @code                std::string generate_json_string(const std::unordered_map<uint8_t, uint64_t>* counter)
 * @brief               Generate JSON string by counter dict
 * @param counter       Counter dict
 * @return              none
 */
std::string generate_json_string(const std::unordered_map<uint8_t, uint64_t>* counter) {
    std::string res;
    res.reserve(300);
    res.append("{");
    for (int i = 0; i < DHCP_MESSAGE_TYPE_COUNT; i++) {
        auto value = std::to_string(counter == nullptr ? 0 : counter->at(i));
        auto json_value = "'" + db_counter_name[i] + "':'" + value + "'";
        res.append(json_value);
        if (i < DHCP_MESSAGE_TYPE_COUNT - 1) {
            res.append(",");
        }
    }
    res.append("}");
    return res;
}

/**
 * @code                void initialize_db_counters(std::string &ifname)
 * @brief               Initialize the counter in counters_db with interface name
 * @param ifname        interface name
 * @return              none
 */
void initialize_db_counters(std::string &ifname)
{
    /**
     * Only add downstream prefix for non-downstream interface
     */
    std::string table_name = construct_counter_db_table_key(ifname);
    auto init_value = generate_json_string(nullptr);
    mCountersDbPtr->hset(table_name, "RX", init_value);
    mCountersDbPtr->hset(table_name, "TX", init_value);
}

/**
 * @code                void increase_cache_counter(std::string &ifname, uint8_t type, dhcp_packet_direction_t dir)
 * @brief               Increase cache counter
 * @param ifname        Interface name
 * @param type          Packet type
 * @param dir           Packet direction
 * @return              none
 */
void increase_cache_counter(std::string &ifname, uint8_t type, dhcp_packet_direction_t dir)
{
    if (type >= DHCP_MESSAGE_TYPE_COUNT) {
        syslog(LOG_WARNING, "Unexpected message type %d(0x%x)\n", type, type);
        type = 0; // treate it as unknown counter
    }
    auto &counter_map = (dir == DHCP_RX) ? rx_counter : tx_counter;
    auto counter = counter_map.find(ifname);
    if (counter == counter_map.end()) {
        syslog(LOG_WARNING, "Cannot find %s counter for %s\n", gen_dir_str(dir, UPPER_CASE).c_str(), ifname.c_str());
        return;
    }
    counter->second[type]++;
}

dhcp_device_context_t *find_device_context(std::unordered_map<std::string, struct intf*> *intfs, std::string if_name) {
    auto intf = intfs->find(if_name);
    if (intf == intfs->end()) {
        return NULL;
    }
    return intf->second->dev_context;
}

/** Number of monitored DHCP message type */
static uint8_t monitored_msg_sz = sizeof(monitored_msgs) / sizeof(*monitored_msgs);

/**
 * @code handle_dhcp_option_53(context, dhcp_option, dir, iphdr, dhcphdr);
 *
 * @brief handle the logic related to DHCP option 53
 *
 * @param src_if        Source pyhsical interface name
 * @param context       Device (interface) context
 * @param dhcp_option   pointer to DHCP option buffer space
 * @param dir           packet direction
 * @param iphdr         pointer to packet IP header
 * @param dhcphdr       pointer to DHCP header
 *
 * @return none
 */
static void handle_dhcp_option_53(std::string &sock_if,
                                  dhcp_device_context_t *context,
                                  const u_char *dhcp_option,
                                  dhcp_packet_direction_t dir,
                                  struct ip *iphdr,
                                  uint8_t *dhcphdr)
{
    in_addr_t giaddr;
    std::string context_if(context->intf);
    dhcp_mon_packet_valid_type_t packet_valid_type = DHCP_INVALID;

    switch (dhcp_option[2])
    {
    // DHCP messages send by client
    case DHCP_MESSAGE_TYPE_DISCOVER:
    case DHCP_MESSAGE_TYPE_REQUEST:
    case DHCP_MESSAGE_TYPE_DECLINE:
    case DHCP_MESSAGE_TYPE_RELEASE:
    case DHCP_MESSAGE_TYPE_INFORM:
        giaddr = ntohl(dhcphdr[DHCP_GIADDR_OFFSET] << 24 | dhcphdr[DHCP_GIADDR_OFFSET + 1] << 16 |
                       dhcphdr[DHCP_GIADDR_OFFSET + 2] << 8 | dhcphdr[DHCP_GIADDR_OFFSET + 3]);
        /**
         * For packets from DHCP client to DHCP server, wouldn't count packets which already have other giaddr
         * 
         * TX packets: means relayed to server. Because one dhcpmon process would capture all packets go through uplink interface, hence
         * we need to compare giaddr to make sure packets are related to current gateway, wouldn'd count packets with giaddr not equal to current gateway
         * 
         * RX packets, means received from client. Even if the packets here are all related on downstream Vlan, but TX packets with giaddr not equal
         * to current gateway wouldn't be counted, to avoid incorrect counting,  wouldn't count RX packets which already have other giaddr
         * 
         * TODO add support to count packets with giaddr no equal to current gateway
         */
        if ((context->giaddr_ip == giaddr && context->is_uplink && dir == DHCP_TX) ||
            (!context->is_uplink && dir == DHCP_RX && (iphdr->ip_dst.s_addr == INADDR_BROADCAST || iphdr->ip_dst.s_addr == context->giaddr_ip) && (giaddr == 0 || context->giaddr_ip == giaddr))) {
            packet_valid_type = DHCP_VALID;
        }
        break;
    // DHCP messages send by server
    case DHCP_MESSAGE_TYPE_OFFER:
    case DHCP_MESSAGE_TYPE_ACK:
    case DHCP_MESSAGE_TYPE_NAK:
    /**
     * For packets from DHCP server to DHCP client, would count packets which already have other giaddr
     * 
     * RX packets: means received from server. If dst ip is gateway, means the packets must target to current gateway, no need to check giaddr in dhcphdr
     * 
     * TX packets: means relayed to client. The packets caputred here must related to corresponding gateway, hence no need to compare giaddr in dhcphdr
     */
        if ((context->giaddr_ip == iphdr->ip_dst.s_addr && context->is_uplink && dir == DHCP_RX) ||
            (!context->is_uplink && dir == DHCP_TX)) {
            packet_valid_type = DHCP_VALID;
        }
        break;
    default:
        syslog(LOG_WARNING, "handle_dhcp_option_53(%s): Unknown DHCP option 53 type %d", context->intf, dhcp_option[2]);
        packet_valid_type = DHCP_UNKNOWN;
        break;
    }

    if (packet_valid_type == DHCP_INVALID) {
        return;
    }

    if (context_if.compare(sock_if) != 0) {
        // count for incomming physical interfaces
        increase_cache_counter(sock_if, dhcp_option[2], dir);
    } else {
        // count for device context interfaces (-d -u -m)
        increase_cache_counter(context_if, dhcp_option[2], dir);
        context->counters[DHCP_COUNTERS_CURRENT][dir][dhcp_option[2]]++;
        aggregate_dev.counters[DHCP_COUNTERS_CURRENT][dir][dhcp_option[2]]++;
    }
}

/**
 * @code client_packet_handler(std::string &sock_if, dhcp_device_context_t *context, uint8_t *buffer,
 *                             ssize_t buffer_sz, dhcp_packet_direction_t dir);
 *
 * @brief packet handler to process received rx and tx packets
 *
 * @param sock_if       socket interface
 * @param context       pointer to device (interface) context
 * @param buffer        DHCP packet
 * @param buffer_sz     buffer that stores received packet data
 * @param dir           DHCP packet direction
 *
 * @return none
 */
static void client_packet_handler(std::string &sock_if, dhcp_device_context_t *context, uint8_t *buffer,
                                  ssize_t buffer_sz, dhcp_packet_direction_t dir)
{
    struct ip *iphdr = (struct ip*) (buffer + IP_START_OFFSET);
    struct udphdr *udp = (struct udphdr*) (buffer + UDP_START_OFFSET);
    uint8_t *dhcphdr = buffer + DHCP_START_OFFSET;
    int dhcp_option_offset = DHCP_START_OFFSET + DHCP_OPTIONS_HEADER_SIZE;

    if (((unsigned)buffer_sz > UDP_START_OFFSET + sizeof(struct udphdr) + DHCP_OPTIONS_HEADER_SIZE) &&
        (ntohs(udp->len) > DHCP_OPTIONS_HEADER_SIZE))
    {
        int dhcp_sz = ntohs(udp->len) < buffer_sz - UDP_START_OFFSET - sizeof(struct udphdr) ?
                    ntohs(udp->len) : buffer_sz - UDP_START_OFFSET - sizeof(struct udphdr);
        int dhcp_option_sz = dhcp_sz - DHCP_OPTIONS_HEADER_SIZE;
        const u_char *dhcp_option = buffer + dhcp_option_offset;
        uint32_t magic_cookie = dhcphdr[MAGIC_COOKIE_OFFSET] << 24 | dhcphdr[MAGIC_COOKIE_OFFSET + 1] << 16 |
                                dhcphdr[MAGIC_COOKIE_OFFSET + 2] << 8 | dhcphdr[MAGIC_COOKIE_OFFSET + 3];
        // If magic cookie not equals to DHCP value, its format is not DHCP format, shouldn't count as DHCP packets.
        if (magic_cookie != DHCP_MAGIC_COOKIE) {
            context->counters[DHCP_COUNTERS_CURRENT][dir][BOOTP_MESSAGE]++;
            aggregate_dev.counters[DHCP_COUNTERS_CURRENT][dir][BOOTP_MESSAGE]++;
            increase_cache_counter(sock_if, BOOTP_MESSAGE, dir);
            return;
        }
        int offset = 0;
        while ((offset < (dhcp_option_sz + 1)) && dhcp_option[offset] != 255) {
            if (dhcp_option[offset] == OPTION_DHCP_MESSAGE_TYPE) {
                if (offset < (dhcp_option_sz + 2)) {
                    handle_dhcp_option_53(sock_if, context, &dhcp_option[offset], dir, iphdr, dhcphdr);
                }
                break; // break while loop since we are only interested in Option 53
            }

            if (dhcp_option[offset] == 0) { // DHCP Option Padding
                offset++;
            } else {
                offset += dhcp_option[offset + 1] + 2;
            }
        }
    }
}

static dhcp_device_context_t *interface_to_dev_context(std::unordered_map<std::string, struct intf*> *devices,
                                                       std::string ifname, bool ignore_standby)
{
    auto vlan = vlan_map.find(ifname);
    if (vlan != vlan_map.end()) {
        if (ignore_standby) {
            std::string state;
            mStateDbMuxTablePtr->hget(ifname, "state", state);
            if (state == "standby") {
                return NULL;
            }
        }
        return find_device_context(devices, vlan->second);
    } else {
        auto port_channel = portchan_map.find(ifname);
        if (port_channel != portchan_map.end()) {
            return find_device_context(devices, port_channel->second);
        }
        else {
            // mgmt interface check
            auto mgmt = mgmt_map.find(ifname);
            if (mgmt != mgmt_map.end()) {
                return find_device_context(devices, mgmt->second);
            }
            return find_device_context(devices, ifname);
        }
    }
    return NULL;
}


/**
 * @code read_tx_callback(fd, event, arg);
 *
 * @brief callback for libevent which is called every time out in order to read queued outgoing packet capture
 *
 * @param fd            socket to read from
 * @param event         libevent triggered event
 * @param arg           user provided argument for callback (interface context)
 *
 * @return none
 */
static void read_tx_callback(int fd, short event, void *arg)
{
    auto devices = (std::unordered_map<std::string, struct intf*> *)arg;
    ssize_t buffer_sz;
    struct sockaddr_ll sll;
    socklen_t slen = sizeof sll;
    dhcp_device_context_t *context = NULL;

    while ((buffer_sz = recvfrom(fd, tx_recv_buffer, snap_length, MSG_DONTWAIT, (struct sockaddr *)&sll, &slen)) > 0) 
    {
        char interfaceName[IF_NAMESIZE];
        if (if_indextoname(sll.sll_ifindex, interfaceName) == NULL) {
            syslog(LOG_WARNING, "invalid output interface index %d\n", sll.sll_ifindex);
            continue;
        }
        std::string intf(interfaceName);
        context = find_device_context(devices, intf);
        if (context) {
            client_packet_handler(intf, context, tx_recv_buffer, buffer_sz, DHCP_TX);
        } else {
            // For packets sent to downstream in standby intf, we don't need to ignore them
            context = interface_to_dev_context(devices, intf, false);
            if (context) {
                client_packet_handler(intf, context, tx_recv_buffer, buffer_sz, DHCP_TX);
            }
        }
    }
}

/**
 * @code read_rx_callback(fd, event, arg);
 *
 * @brief callback for libevent which is called every time out in order to read queued incoming packet capture
 *
 * @param fd            socket to read from
 * @param event         libevent triggered event
 * @param arg           user provided argument for callback (interface context)
 *
 * @return none
 */
static void read_rx_callback(int fd, short event, void *arg)
{
    auto devices = (std::unordered_map<std::string, struct intf*> *)arg;
    ssize_t buffer_sz;
    struct sockaddr_ll sll;
    socklen_t slen = sizeof(sll);
    dhcp_device_context_t *context = NULL;

    while ((buffer_sz = recvfrom(fd, rx_recv_buffer, snap_length, MSG_DONTWAIT, (struct sockaddr *)&sll, &slen)) > 0) 
    {
        char interfaceName[IF_NAMESIZE];
        if (if_indextoname(sll.sll_ifindex, interfaceName) == NULL) {
            syslog(LOG_WARNING, "invalid input interface index %d\n", sll.sll_ifindex);
            continue;
        }
        std::string intf(interfaceName);
        context = find_device_context(devices, intf);
        // If context interface is not equal to physical interface, for single rx packet, we would
        // capture it in context interface and physical interface.
        // 1. For non-dualtor, it's okay to directly invoke `client_packet_handler` to count
        // 2. For dualtor, rx packets come from (downlink) standby interfaces should be dropped, hence directly
        //    invoking `client_packet_handler` maybe cause mis-count in context interface for packets come from
        //    standby interfaces.
        //    1) For uplink: update context interface counter and physical interface count when capture packets
        //    2) For downlink:
        //       - Ignore packet captured in context interface
        //       - When capture packet in non-standby Physical interface, update context interface and physical
        //         interface count together
        if (dual_tor_sock) {
            if (context && context->is_uplink) {
                // RX interface is uplink context interface, not need to care the mux status
                // Update RX uplink context intf count
                client_packet_handler(intf, context, rx_recv_buffer, buffer_sz, DHCP_RX);
            } else if (!context) {
                // RX interface is pc member interface or vlan member interface
                // Update RX Physical
                context = interface_to_dev_context(devices, intf, true);
                if (context) {
                    // Update physical interface count
                    client_packet_handler(intf, context, rx_recv_buffer, buffer_sz, DHCP_RX);
                    if (!context->is_uplink) {
                        // Update downlink context interface count
                        client_packet_handler(downstream_if_name, context, rx_recv_buffer, buffer_sz, DHCP_RX);
                    }
                }
            }
        } else {
            // non-dualtor
            if (!context) {
                context = interface_to_dev_context(devices, intf, false);
            }
            if (context) {
                client_packet_handler(intf, context, rx_recv_buffer, buffer_sz, DHCP_RX);
            }
        }
    }
}

/**
 * @code dhcp_device_is_dhcp_inactive(counters);
 *
 * @brief Check if there were no DHCP activity
 *
 * @param counters  current/snapshot counter
 *
 * @return true if there were no DHCP activity, false otherwise
 */
static bool dhcp_device_is_dhcp_inactive(uint64_t counters[][DHCP_DIR_COUNT][DHCP_MESSAGE_TYPE_COUNT])
{
    uint64_t *rx_counters = counters[DHCP_COUNTERS_CURRENT][DHCP_RX];
    uint64_t *rx_counter_snapshot = counters[DHCP_COUNTERS_SNAPSHOT][DHCP_RX];

    bool rv = true;
    for (uint8_t i = 0; (i < monitored_msg_sz) && rv; i++) {
        rv = rx_counters[monitored_msgs[i]] == rx_counter_snapshot[monitored_msgs[i]];
    }

    return rv;
}

/**
 * @code dhcp_device_is_dhcp_msg_unhealthy(type, counters);
 *
 * @brief Check if DHCP relay is functioning properly for message of type 'type'.
 *        For every rx of message 'type', there should be increment of the same message type.
 *
 * @param type      DHCP message type
 * @param counters  current/snapshot counter
 *
 * @return true if DHCP message 'type' is transmitted,false otherwise
 */
static bool dhcp_device_is_dhcp_msg_unhealthy(dhcp_message_type_t type,
                                              uint64_t counters[][DHCP_DIR_COUNT][DHCP_MESSAGE_TYPE_COUNT])
{
    // check if DHCP message 'type' is being relayed
    return ((counters[DHCP_COUNTERS_CURRENT][DHCP_RX][type] >  counters[DHCP_COUNTERS_SNAPSHOT][DHCP_RX][type]) &&
            (counters[DHCP_COUNTERS_CURRENT][DHCP_TX][type] <= counters[DHCP_COUNTERS_SNAPSHOT][DHCP_TX][type])    );
}

/**
 * @code dhcp_device_check_positive_health(counters, counters_snapshot);
 *
 * @brief Check if DHCP relay is functioning properly for monitored messages (Discover, Offer, Request, ACK.)
 *        For every rx of monitored messages, there should be increment of the same message type.
 *
 * @param counters  current/snapshot counter
 *
 * @return DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
static dhcp_mon_status_t dhcp_device_check_positive_health(uint64_t counters[][DHCP_DIR_COUNT][DHCP_MESSAGE_TYPE_COUNT])
{
    dhcp_mon_status_t rv = DHCP_MON_STATUS_HEALTHY;

    bool is_dhcp_unhealthy = false;
    for (uint8_t i = 0; (i < monitored_msg_sz) && !is_dhcp_unhealthy; i++) {
        is_dhcp_unhealthy = dhcp_device_is_dhcp_msg_unhealthy(monitored_msgs[i], counters);
    }

    // if we have rx DORA then we should have corresponding tx DORA (DORA being relayed)
    if (is_dhcp_unhealthy) {
        rv = DHCP_MON_STATUS_UNHEALTHY;
    }

    return rv;
}

/**
 * @code dhcp_device_check_negative_health(counters);
 *
 * @brief Check that DHCP relayed messages are not being transmitted out of this interface/dev
 *        using its counters. The interface is negatively healthy if there are not DHCP message
 *        travelling through it.
 *
 * @param counters              recent interface counter
 * @param counters_snapshot     snapshot counters
 *
 * @return DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
static dhcp_mon_status_t dhcp_device_check_negative_health(uint64_t counters[][DHCP_DIR_COUNT][DHCP_MESSAGE_TYPE_COUNT])
{
    dhcp_mon_status_t rv = DHCP_MON_STATUS_HEALTHY;

    uint64_t *tx_counters = counters[DHCP_COUNTERS_CURRENT][DHCP_TX];
    uint64_t *tx_counter_snapshot = counters[DHCP_COUNTERS_SNAPSHOT][DHCP_TX];

    bool is_dhcp_unhealthy = false;
    for (uint8_t i = 0; (i < monitored_msg_sz) && !is_dhcp_unhealthy; i++) {
        is_dhcp_unhealthy = tx_counters[monitored_msgs[i]] > tx_counter_snapshot[monitored_msgs[i]];
    }

    // for negative validation, return unhealthy if DHCP packet are being
    // transmitted out of the device/interface
    if (is_dhcp_unhealthy) {
        rv = DHCP_MON_STATUS_UNHEALTHY;
    }

    return rv;
}

/**
 * @code dhcp_device_check_health(check_type, counters, counters_snapshot);
 *
 * @brief Check that DHCP relay is functioning properly given a check type. Positive check
 *        indicates for every rx of DHCP message of type 'type', there would increment of
 *        the corresponding TX of the same message type. While negative check indicates the
 *        device should not be actively transmitting any DHCP messages. If it does, it is
 *        considered unhealthy.
 *
 * @param check_type    type of health check
 * @param counters      current/snapshot counter
 *
 * @return DHCP_MON_STATUS_HEALTHY, DHCP_MON_STATUS_UNHEALTHY, or DHCP_MON_STATUS_INDETERMINATE
 */
static dhcp_mon_status_t dhcp_device_check_health(dhcp_mon_check_t check_type,
                                                  uint64_t counters[][DHCP_DIR_COUNT][DHCP_MESSAGE_TYPE_COUNT])
{
    dhcp_mon_status_t rv = DHCP_MON_STATUS_HEALTHY;

    if (dhcp_device_is_dhcp_inactive(aggregate_dev.counters)) {
        rv = DHCP_MON_STATUS_INDETERMINATE;
    } else if (check_type == DHCP_MON_CHECK_POSITIVE) {
        rv = dhcp_device_check_positive_health(counters);
    } else if (check_type == DHCP_MON_CHECK_NEGATIVE) {
        rv = dhcp_device_check_negative_health(counters);
    }

    return rv;
}

/**
 * @code dhcp_print_counters(vlan_intf, type, counters);
 *
 * @brief prints DHCP counters to sylsog.
 *
 * @param vlan_intf vlan interface name
 * @param type      counter type
 * @param counters  interface counter
 *
 * @return none
 */
static void dhcp_print_counters(const char *vlan_intf,
                                dhcp_counters_type_t type,
                                uint64_t counters[][DHCP_MESSAGE_TYPE_COUNT])
{
    static const char *counter_desc[DHCP_COUNTERS_COUNT] = {
        [DHCP_COUNTERS_CURRENT] = " Current",
        [DHCP_COUNTERS_SNAPSHOT] = "Snapshot"
    };

    syslog(
        LOG_NOTICE,
        "[%*s-%*s rx/tx] Discover: %*" PRIu64 "/%*" PRIu64 ", Offer: %*" PRIu64 "/%*" PRIu64 
        ", Request: %*" PRIu64 "/%*" PRIu64 ", ACK: %*" PRIu64 "/%*" PRIu64 "\n",
        IF_NAMESIZE, vlan_intf,
        (int) strlen(counter_desc[type]), counter_desc[type],
        DHCP_COUNTER_WIDTH, counters[DHCP_RX][DHCP_MESSAGE_TYPE_DISCOVER],
        DHCP_COUNTER_WIDTH, counters[DHCP_TX][DHCP_MESSAGE_TYPE_DISCOVER],
        DHCP_COUNTER_WIDTH, counters[DHCP_RX][DHCP_MESSAGE_TYPE_OFFER],
        DHCP_COUNTER_WIDTH, counters[DHCP_TX][DHCP_MESSAGE_TYPE_OFFER],
        DHCP_COUNTER_WIDTH, counters[DHCP_RX][DHCP_MESSAGE_TYPE_REQUEST],
        DHCP_COUNTER_WIDTH, counters[DHCP_TX][DHCP_MESSAGE_TYPE_REQUEST],
        DHCP_COUNTER_WIDTH, counters[DHCP_RX][DHCP_MESSAGE_TYPE_ACK],
        DHCP_COUNTER_WIDTH, counters[DHCP_TX][DHCP_MESSAGE_TYPE_ACK]
    );
}

/**
 * @code init_socket();
 *
 * @brief initializes rx/tx sockets, bind it to interface and bpf program
 *
 * @return 0 on success, otherwise for failure
 */
static int init_socket()
{
    int rv = -1;

    do {
        auto rx_sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
        auto tx_sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
        if (rx_sock < 0 || tx_sock < 0) {
            syslog(LOG_ALERT, "socket: failed to open socket with '%s'\n", strerror(errno));
            exit(1);
        }

        struct sockaddr_ll rx_addr;
        memset(&rx_addr, 0, sizeof(rx_addr));
        rx_addr.sll_ifindex = 0; // any interface
        rx_addr.sll_family = AF_PACKET;
        rx_addr.sll_protocol = htons(ETH_P_ALL);
        if (bind(rx_sock, (struct sockaddr *) &rx_addr, sizeof(rx_addr))) {
            syslog(LOG_ALERT, "bind: failed to bind to all interface with '%s'\n", strerror(errno));
            break;
        }

        struct sockaddr_ll tx_addr;
        memset(&tx_addr, 0, sizeof(tx_addr));
        tx_addr.sll_ifindex = 0; // any interface
        tx_addr.sll_family = AF_PACKET;
        tx_addr.sll_protocol = htons(ETH_P_ALL);
        if (bind(tx_sock, (struct sockaddr *) &tx_addr, sizeof(tx_addr))) {
            syslog(LOG_ALERT, "bind: failed to bind to interface with '%s'\n", strerror(errno));
            exit(1);
        }

        for (auto &itr : intfs) {
            itr.second->dev_context->rx_sock = rx_sock;
            itr.second->dev_context->tx_sock = tx_sock;
        }
        rv = 0;
    } while (0);

    return rv;
}

static void init_recv_buffers(int snaplen)
{
    snap_length = snaplen;
    rx_recv_buffer = (uint8_t *) malloc(snaplen);
    if (rx_recv_buffer == NULL) {
        syslog(LOG_ALERT, "malloc: failed to allocate memory for socket rx buffer '%s'\n", strerror(errno));
        exit(1);
    }

    tx_recv_buffer = (uint8_t *) malloc(snaplen);
    if (tx_recv_buffer == NULL) {
        syslog(LOG_ALERT, "malloc: failed to allocate memory for socket tx buffer '%s'\n", strerror(errno));
        exit(1);
    }
}

/**
 * @code initialize_intf_mac_and_ip_addr(context);
 *
 * @brief initializes device (interface) mac/ip addresses
 *
 * @param context           pointer to device (interface) context
 *
 * @return 0 on success, otherwise for failure
 */
int initialize_intf_mac_and_ip_addr(dhcp_device_context_t *context)
{
    int rv = -1;

    do {
        int fd;
        struct ifreq ifr;
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            syslog(LOG_ALERT, "socket: %s", strerror(errno));
            break;
        }

        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, context->intf, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

        // Get network address
        if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
            syslog(LOG_ALERT, "ioctl: %s", explain_ioctl(fd, SIOCGIFADDR, &ifr));
            break;
        }
        context->ip = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr;

        // Get mac address
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
            syslog(LOG_ALERT, "ioctl: %s", explain_ioctl(fd, SIOCGIFHWADDR, &ifr));
            break;
        }
        memcpy(context->mac, ifr.ifr_hwaddr.sa_data, sizeof(context->mac));

        close(fd);

        rv = 0;
    } while (0);

    return rv;
}

/**
 * @code dhcp_device_get_ip(context);
 *
 * @brief Accessor method
 *
 * @param context       pointer to device (interface) context
 *
 * @return interface IP
 */
int dhcp_device_get_ip(dhcp_device_context_t *context, in_addr_t *ip)
{
    int rv = -1;

    if (context != NULL && ip != NULL) {
        *ip = context->ip;
        rv = 0;
    }

    return rv;
}

/**
 * @code dhcp_device_get_aggregate_context();
 *
 * @brief Accessor method
 *
 * @return pointer to aggregate device (interface) context
 */
dhcp_device_context_t* dhcp_device_get_aggregate_context()
{
    return &aggregate_dev;
}

/**
 * @code dhcp_device_get_counter(dhcp_packet_direction_t dir);
 * @brief Accessor method
 * @return pointer to counter
 */
std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>>* dhcp_device_get_counter(dhcp_packet_direction_t dir)
{
    return (dir == DHCP_RX ? &rx_counter : &tx_counter);
}

/**
 * @code dhcp_device_init(context, intf, is_uplink);
 *
 * @brief initializes device (interface) that handles packet capture per interface.
 */
int dhcp_device_init(dhcp_device_context_t **context, const char *intf, uint8_t is_uplink)
{
    int rv = -1;
    dhcp_device_context_t *dev_context = NULL;

    if ((context != NULL) && (strlen(intf) < sizeof(dev_context->intf))) {
        dev_context = (dhcp_device_context_t *) malloc(sizeof(dhcp_device_context_t));
        if (dev_context != NULL) {
            // set device name
            strncpy(dev_context->intf, intf, sizeof(dev_context->intf) - 1);
            dev_context->intf[sizeof(dev_context->intf) - 1] = '\0';
            // set device meta data
            if (initialize_intf_mac_and_ip_addr(dev_context) == 0) {
                dev_context->is_uplink = is_uplink;
                memset(dev_context->counters, 0, sizeof(dev_context->counters));
                *context = dev_context;
                rv = 0;
            }
        }
        else {
            syslog(LOG_ALERT, "malloc: failed to allocated device context memory for '%s'", dev_context->intf);
        }
    }

    return rv;
}

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
int dhcp_device_start_capture(size_t snaplen, struct event_mgr *rx_event_mgr, struct event_mgr *tx_event_mgr, in_addr_t giaddr_ip)
{
    int rv = -1;
    int rx_sock = -1, tx_sock = -1;

    do {
        if (snaplen < UDP_START_OFFSET + sizeof(struct udphdr) + DHCP_OPTIONS_HEADER_SIZE) {
            syslog(LOG_ALERT, "dhcp_device_start_capture: snap length is too low to capture DHCP options");
            exit(1);
        }

        init_socket();

        init_recv_buffers(snaplen);

        update_vlan_mapping(mConfigDbPtr);
        update_portchannel_mapping(mConfigDbPtr);
        update_mgmt_mapping();

        for (auto &itr : intfs) {
            itr.second->dev_context->snaplen = snaplen;
            itr.second->dev_context->giaddr_ip = giaddr_ip;
            // all interface dev context has same rx/tx socket
            rx_sock = itr.second->dev_context->rx_sock;
            tx_sock = itr.second->dev_context->tx_sock;
        }

        if (rx_sock == -1 || tx_sock == -1) {
            syslog(LOG_ALERT, "dhcp_device_start_capture: invalid rx_sock or tx_sock");
            exit(1);
        }
        if (setsockopt(rx_sock, SOL_SOCKET, SO_ATTACH_FILTER, &dhcp_inbound_sock_bfp, sizeof(dhcp_inbound_sock_bfp)) != 0) {
            syslog(LOG_ALERT, "setsockopt: failed to attach filter with '%s'\n", strerror(errno));
            exit(1);
        }

        if (setsockopt(tx_sock, SOL_SOCKET, SO_ATTACH_FILTER, &dhcp_outbound_sock_bfp, sizeof(dhcp_outbound_sock_bfp)) != 0) {
            syslog(LOG_ALERT, "setsockopt: failed to attach filter with '%s'\n", strerror(errno));
            exit(1);
        }

        struct event *rx_event = event_new(rx_event_mgr->get_base(), rx_sock, EV_READ | EV_PERSIST, read_rx_callback, &intfs);
        struct event *tx_event = event_new(tx_event_mgr->get_base(), tx_sock, EV_READ | EV_PERSIST, read_tx_callback, &intfs);

        if (rx_event == NULL || tx_event == NULL) {
            syslog(LOG_ALERT, "event_new: failed to allocate memory for libevent event '%s'\n", strerror(errno));
            exit(1);
        }

        if (rx_event_mgr->add_event(rx_event, NULL) != 0 || tx_event_mgr->add_event(tx_event, NULL) != 0) {
            syslog(LOG_ERR, "add_event: failed to add event for packets tx/rx\n");
            exit(1);
        }

        rv = 0;
    } while (0);

    return rv;
}

/**
 * @code dhcp_device_shutdown(context);
 *
 * @brief shuts down device (interface). Also, stops packet capture on interface and cleans up any allocated memory
 */
void dhcp_device_shutdown(dhcp_device_context_t *context)
{
    free(context);
}

/**
 * @code dhcp_device_get_status(check_type, context);
 *
 * @brief collects DHCP relay status info for a given interface. If context is null, it will report aggregate
 *        status
 */
dhcp_mon_status_t dhcp_device_get_status(dhcp_mon_check_t check_type, dhcp_device_context_t *context)
{
    dhcp_mon_status_t rv = DHCP_MON_STATUS_HEALTHY;

    if (context != NULL) {
        rv = dhcp_device_check_health(check_type, context->counters);
    }

    return rv;
}

/**
 * @code dhcp_device_update_snapshot(context);
 *
 * @brief Update device/interface counters snapshot
 */
void dhcp_device_update_snapshot(dhcp_device_context_t *context)
{
    if (context != NULL) {
        memcpy(context->counters[DHCP_COUNTERS_SNAPSHOT],
               context->counters[DHCP_COUNTERS_CURRENT],
               sizeof(context->counters[DHCP_COUNTERS_SNAPSHOT]));
    }
}

/**
 * @code dhcp_device_print_status(context, type);
 *
 * @brief prints status counters to syslog.
 */
void dhcp_device_print_status(dhcp_device_context_t *context, dhcp_counters_type_t type)
{
    if (context != NULL) {
        dhcp_print_counters(context->intf, type, context->counters[type]);
    }
}
