/**
 * @file socket_manager.cpp
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>

#include "sock_mgr.h"

#include "packet_handler.h"     /** for attaching packet handler */
#include "util.h"               /** for db counter key generation */
#include <swss/subscriberstatetable.h>

int rx_sock, tx_sock, rx_sock_v6, tx_sock_v6;

/** String identifier of sock fd for printing */
static const char rx_sock_name[] = "rx";
static const char tx_sock_name[] = "tx";
static const char rx_sock_name_v6[] = "rx_v6";
static const char tx_sock_name_v6[] = "tx_v6";

/** BPF filters for different sockets */
static const char dhcp_inbound_filter[] = "inbound and ip and udp and (port 67 or port 68)";
static const char dhcp_outbound_filter[] = "outbound and ip and udp and (port 67 or port 68)";
static const char dhcpv6_inbound_filter[] = "inbound and ip6 and udp and (port 547 or port 546)";
static const char dhcpv6_outbound_filter[] = "outbound and ip6 and udp and (port 547 or port 546)";

/** Tags for different events, so we can triiger only one type */
static const char packet_handler_tag[] = "PacketHandler";
static const char cache_counter_updater_tag[] = "CacheCounterUpdater";

/* sock fd to sock_info mapping */
std::unordered_map<int, sock_info_t> sock_map;

extern std::shared_ptr<swss::DBConnector> mCountersDbPtr;

extern std::string downstream_ifname;

/**
 * @code opensocket();
 *
 * @brief open and bind to a socket
 *
 * @return positive socket number on success, negative for failure
 */
static int open_socket()
{
    int sock = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (sock < 0) {
        syslog(LOG_ALERT, "socket: failed to open socket with %s", strerror(errno));
        return sock;
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    
    addr.sll_ifindex = 0; // any interface
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        syslog(LOG_ALERT, "bind: failed to bind to all interface with %s", strerror(errno));
        close(sock);
        return -1;
    }

    syslog(LOG_INFO, "Opened and bound socket %d to all interfaces", sock);

    return sock;
}

/**
 * @code init_socket();
 *
 * @brief initializes rx/tx sockets, bind it to interface and bpf program
 *
 * @return 0 on success, negative on failure
 */
static int init_socket()
{
    rx_sock = open_socket();
    if (rx_sock < 0) {
        syslog(LOG_ALERT, "Failed to open and bind socket");
        goto no_close;
    }
    tx_sock = open_socket();
    if (tx_sock < 0) {
        syslog(LOG_ALERT, "Failed to open and bind socket");
        goto close_rx_sock;
    }
    rx_sock_v6 = open_socket();
    if (rx_sock_v6 < 0) {
        syslog(LOG_ALERT, "Failed to open and bind socket");
        goto close_tx_sock;
    }
    tx_sock_v6 = open_socket();
    if (tx_sock_v6 < 0) {
        syslog(LOG_ALERT, "Failed to open and bind socket");
        goto close_rx_sock_v6;
    }

    syslog(LOG_INFO, "Initialized all sockets successfully");
    syslog(LOG_INFO, "  rx_sock=%d, tx_sock=%d, rx_sock_v6=%d, tx_sock_v6=%d",
           rx_sock, tx_sock, rx_sock_v6, tx_sock_v6);

    return 0;

close_tx_sock_v6:
    close(tx_sock_v6);
close_rx_sock_v6:
    close(rx_sock_v6);
close_tx_sock:
    close(tx_sock);
close_rx_sock:
    close(rx_sock);
no_close:
    return -1;
}

/**
 * @code free_socket()
 *
 * @brief undo what init_socket does
 */
static void free_socket()
{
    close(tx_sock_v6);
    close(rx_sock_v6);
    close(tx_sock);
    close(rx_sock);
    syslog(LOG_INFO, "Closed all opened sockets");
    syslog(LOG_INFO, "  rx_sock=%d, tx_sock=%d, rx_sock_v6=%d, tx_sock_v6=%d",
           rx_sock, tx_sock, rx_sock_v6, tx_sock_v6);
}

/**
 * @code print_bpf_prog(bp)
 * @brief helper function to print bpf program instructions
 */
static void print_bpf_prog(const struct bpf_program *bp) {
    for (unsigned int i = 0; i < bp->bf_len; ++i) {
        const struct bpf_insn *ins = &bp->bf_insns[i];
        syslog(LOG_INFO, "[%02u] code=0x%04x jt=%u jf=%u k=0x%08x",
               i, ins->code, ins->jt, ins->jf, ins->k);
    }
}

/**
 * @code _compile_bpf_prog(handle, bp, filter, fprog)
 *
 * @brief helper function to compile filter to bpf byte code and store in fprog
 */
static int _compile_bpf_prog(pcap_t *handle, struct bpf_program *bp, const char *filter, struct sock_fprog *fprog){
    syslog(LOG_INFO, "Compiling filter %s to bpf prog", filter);

    if (pcap_compile(handle, bp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        syslog(LOG_ALERT, "pcap_compile: failed to compile filter %s: %s", filter, pcap_geterr(handle));
        return -1;
    }
    
    fprog->filter = (struct sock_filter *)malloc(bp->bf_len * sizeof(struct bpf_insn));
    if (fprog->filter == NULL) {
        syslog(LOG_ALERT, "malloc: failed to allocate memory for bpf program");
        pcap_freecode(bp);
        return -1;
    }
    memcpy(fprog->filter, bp->bf_insns, bp->bf_len * sizeof(struct bpf_insn));
    fprog->len = bp->bf_len;

    print_bpf_prog(bp);
    pcap_freecode(bp);

    return 0;
}

/**
 * @code free_all_bpf_prog()
 *
 * @brief undo compile_all_bpf_prog did
 */
static void sock_mgr_free_all_bpf_prog()
{
    for (auto &[sock, info] : sock_map) {
        if (info.bpf_prog.filter != NULL) {
            free(info.bpf_prog.filter);
        }
    }
}

/**
 * @code compile_all_bpf_prog();
 *
 * @brief compile all 4 tcpdump filters into classic bpf progs
 */
static int sock_mgr_compile_all_bpf_prog()
{
    syslog(LOG_INFO, "Compiling all bpf progs for sock mgr");

    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == NULL) {
        syslog(LOG_ALERT, "pcap_open_dead: failed to create handle");
        return -1;
    }

    syslog(LOG_INFO, "Opened pcap handle");

    struct bpf_program bp;
    for (auto &[sock, info] : sock_map) {
        if (_compile_bpf_prog(handle, &bp, info.filter, &info.bpf_prog) < 0) {
            syslog(LOG_ALERT, "Failed to compile %s into bpf prog", info.filter);
            sock_mgr_free_all_bpf_prog();
            pcap_close(handle);
            return -1;
        }
    }

    pcap_close(handle);
    syslog(LOG_INFO, "Closed pcap handle");

    return 0;
}

/**
 * @code attach_all_bpf_prog();
 *
 * @brief attach all bpf progs to sockets, and immediately drain all unfiltered packets
 */
static int sock_mgr_attach_all_bpf_prog()
{
    syslog(LOG_INFO, "Attaching all bpf progs to sockets");

    for (const auto &[sock, info] : sock_map) {
        if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &info.bpf_prog, sizeof(struct sock_fprog)) < 0) {
            syslog(LOG_ALERT, "setsockopt: failed to attach filter %s with %s", info.filter, strerror(errno));
            return -1;
        }
        syslog(LOG_INFO, "Attached filter %s to socket %d %s successfully", info.filter, sock, info.name);
    }

    return 0;
}

/**
 * @code free_all_buffer()
 *
 * @brief free all allocated buffers for all sockets
 */
static void sock_mgr_free_all_buffer()
{
    for (auto &[sock, info] : sock_map) {
        if (info.buffer != NULL) {
            free(info.buffer);
            info.buffer = NULL;
        }
    }
}

/**
 * @code init_all_buffer()
 *
 * @brief allocate all buffers for all sockets
 */
static int sock_mgr_init_all_buffer()
{
    for (auto &[sock, info] : sock_map) {
        if (posix_memalign((void **)&info.buffer, 64, info.snaplen) < 0) {
            syslog(LOG_ALERT, "posix_memalign: failed to allocate memory for socket buffer %s", strerror(errno));
            sock_mgr_free_all_buffer();
            return -1;
        }
    }

    return 0;
}

int sock_mgr_init(uint32_t snaplen)
{
    syslog(LOG_INFO, "Initializing sock mgr with snaplen %u", snaplen);

    if (init_socket() < 0) {
        syslog(LOG_ALERT, "Failed to open and bind sockets");
        goto no_free;
    }

    sock_map[rx_sock] = sock_info_t {
        .sock = rx_sock,
        .name = rx_sock_name,
        .is_rx = true,
        .is_v6 = false,
        .snaplen = snaplen,
        .filter = dhcp_inbound_filter, 
        .all_counters = all_counters_t(),
        .all_counters_snapshot = all_counters_t(),
        .packet_handler = (void *)packet_handler,
    };

    sock_map[tx_sock] = sock_info_t {
        .sock = tx_sock,
        .name = tx_sock_name,
        .is_rx = false,
        .is_v6 = false,
        .snaplen = snaplen,
        .filter = dhcp_outbound_filter, 
        .all_counters = all_counters_t(),
        .all_counters_snapshot = all_counters_t(),
        .packet_handler = (void *)packet_handler,
    };

    sock_map[rx_sock_v6] = sock_info_t {
        .sock = rx_sock_v6,
        .name = rx_sock_name_v6,
        .is_rx = true,
        .is_v6 = true,
        .snaplen = snaplen,
        .filter = dhcpv6_inbound_filter, 
        .all_counters = all_counters_t(),
        .all_counters_snapshot = all_counters_t(),
        .packet_handler = (void *)packet_handler_v6,
    };

    sock_map[tx_sock_v6] = sock_info_t {
        .sock = tx_sock_v6,
        .name = tx_sock_name_v6,
        .is_rx = false,
        .is_v6 = true,
        .snaplen = snaplen,
        .filter = dhcpv6_outbound_filter, 
        .all_counters = all_counters_t(),
        .all_counters_snapshot = all_counters_t(),
        .packet_handler = (void *)packet_handler_v6,
    };

    if (sock_mgr_init_all_buffer() < 0) {
        syslog(LOG_ALERT, "Failed to initialize all socket buffers");
        goto free_socket;
    }

    if (sock_mgr_compile_all_bpf_prog() < 0) {
        syslog(LOG_ALERT, "Failed to compile all bpf prog");
        goto free_buffer;
    }

    if (sock_mgr_attach_all_bpf_prog() < 0) {
        syslog(LOG_ALERT, "Failed to attach bpf prog");
        goto free_bpf;
    }

    syslog(LOG_INFO, "Initialized sock mgr successfully");

    return 0;

free_bpf:
    sock_mgr_free_all_bpf_prog();
free_buffer:
    sock_mgr_free_all_buffer();
    sock_map.clear();
free_socket:
    free_socket();
no_free:
    return -1;
}

void sock_mgr_free()
{
    sock_mgr_free_all_bpf_prog();
    sock_mgr_free_all_buffer();
    sock_map.clear();
    free_socket();
}

int sock_mgr_init_event_mgr()
{
    syslog(LOG_INFO, "Initializing event manager for all sockets");
    for (auto &[sock, info] : sock_map) {
        info.event_mgr_ptr = new event_mgr(info.name);
        if (info.event_mgr_ptr->init_base() < 0) {
            syslog(LOG_ALERT, "Failed to initialize event manager %s", info.name);
            sock_mgr_free_event_mgr();
            return -1;
        }
    }

    return 0;
}

void sock_mgr_free_event_mgr()
{
    for (auto &[sock, info] : sock_map) {
        if (info.event_mgr_ptr != NULL) {
            info.event_mgr_ptr->free();
            delete info.event_mgr_ptr;
            info.event_mgr_ptr = NULL;
        }
    }
}

int sock_mgr_register_packet_handler()
{
    syslog(LOG_INFO, "Registering packet handlers for all sockets");

    for (const auto &[sock, info] : sock_map) {
        struct event *listen_event = event_new(info.event_mgr_ptr->get_base(), sock, EV_READ | EV_PERSIST, callback_common, NULL);
        if (listen_event == NULL) {
            syslog(LOG_ALERT, "event_new: failed to allocate memory for libevent event %s", strerror(errno));
            sock_mgr_unregister_packet_handler();
            return -1;
        }
        if (info.event_mgr_ptr->add_event(listen_event, NULL, packet_handler_tag) < 0) {
            syslog(LOG_ALERT, "add_event: failed to add event for socket %d %s", sock, info.name);
            event_free(listen_event);
            sock_mgr_unregister_packet_handler();
            return -1;
        }
    }

    return 0;
}

void sock_mgr_unregister_packet_handler()
{
    syslog(LOG_INFO, "Unregistering packet handlers for all sockets");

    for (const auto &[sock, info] : sock_map) {
        info.event_mgr_ptr->del_all_events(packet_handler_tag);
    }
}

int sock_mgr_register_cache_counter_updater(event_callback_fn callback)
{
    syslog(LOG_INFO, "Registering cache counter updater for all sockets");

    for (const auto &[sock, info] : sock_map) {
        struct event *event = event_new(info.event_mgr_ptr->get_base(), -1, 0, callback, (void *)&sock);
        if (event == NULL) {
            syslog(LOG_ALERT, "event_new: failed to allocate memory for cache counter updater event %s", strerror(errno));
            sock_mgr_unregister_cache_counter_updater();
            return -1;
        }
        if (info.event_mgr_ptr->add_event(event, NULL, cache_counter_updater_tag) < 0) {
            syslog(LOG_ALERT, "add_event: failed to add cache counter updater event for socket %d %s", sock, info.name);
            event_free(event);
            sock_mgr_unregister_cache_counter_updater();
            return -1;
        }
    }

    return 0;
}

void sock_mgr_unregister_cache_counter_updater()
{
    syslog(LOG_INFO, "Unregistering cache counter updater for all sockets");

    for (const auto &[sock, info] : sock_map) {
        info.event_mgr_ptr->del_all_events(cache_counter_updater_tag);
    }
}

void sock_mgr_pause_write_cache_to_db()
{
    for (auto &[sock, info] : sock_map) {
        info.pause_write_cache_to_db = true;
    }
}

void sock_mgr_clear_pause_write_cache_to_db()
{
    for (auto &[sock, info] : sock_map) {
        info.pause_write_cache_to_db = false;
    }
}

bool sock_mgr_pause_write_cache_to_db_all_cleared()
{
    for (const auto &[sock, info] : sock_map) {
        if (info.pause_write_cache_to_db) {
            return false;
        }
    }
    return true;
}

void sock_mgr_trigger_cache_counter_updater()
{
    for (const auto &[sock, info] : sock_map) {
        info.event_mgr_ptr->activate_all_events(cache_counter_updater_tag);
    }
}

void sock_mgr_drain_sock_buffer()
{
    char buf[65536];

    syslog(LOG_INFO, "Draining all unfiltered packets from all sockets");

    for (const auto &[sock, info] : sock_map) {
        while (recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL) > 0);
        syslog(LOG_INFO, "Drained all unfiltered packets from socket %d %s", sock, info.name);
    }
}

void sock_mgr_start_event_loop()
{
    syslog(LOG_INFO, "Starting event loop for all sockets");

    for (auto &[sock, info] : sock_map) {
        info.event_thread = std::thread([&info]() {
        if (event_base_dispatch(info.event_mgr_ptr->get_base()) < 0) {
            syslog(LOG_ALERT, "Could not start %s libevent dispatching loop!", info.name);
        }
        });
    }
}

void sock_mgr_wait_event_loop()
{
    syslog(LOG_INFO, "Waiting event loop for all sockets to end");

    for (auto &[sock, info] : sock_map) {
        info.event_thread.join();
    }
}

void sock_mgr_stop_event_loop()
{
    syslog(LOG_INFO, "Stopping event loop for all sockets");

    for (auto &[sock, info] : sock_map) {
        event_base_loopbreak(info.event_mgr_ptr->get_base());
    }
}

void sock_mgr_update_snapshot()
{
    syslog_debug(LOG_INFO, "Updating snapshot for all sockets");

    for (auto &[sock, info] : sock_map) {
        info.all_counters_snapshot = info.all_counters;
    }
}

/**
 * @code counter_unchanged(counter, counter_snapshot, monitored_msgs, monitored_msg_cnt);
 * @brief helper function to check if counter is unchanged compared to snapshot for given monitored message types
 * @param counter               current counter
 * @param counter_snapshot      snapshot counter
 * @param monitored_msgs        array of monitored message types
 * @param monitored_msg_cnt     number of monitored message types
 * @return                      true if unchanged, false otherwise
 */
static bool counter_unchanged(const counter_t &counter, const counter_t &counter_snapshot, const int *monitored_msgs, size_t monitored_msg_cnt)
{
    if (counter.size() != counter_snapshot.size()) {
        return false;
    }
    for (int i = 0; i < monitored_msg_cnt; i++) {
        uint8_t msg_type = monitored_msgs[i];
        if (counter.at(msg_type) != counter_snapshot.at(msg_type)) {
            return false;
        }
    }
    return true;
}

bool sock_mgr_counters_unchanged(const std::string &ifname, const int *monitored_msgs, size_t monitored_msg_cnt, const int *monitored_v6_msgs, size_t monitored_v6_msg_cnt)
{
    for (const auto &[sock, info] : sock_map) {
        const counter_t &counter = info.all_counters.at(ifname);
        const counter_t &counter_snapshot = info.all_counters_snapshot.at(ifname);
        if (counter.size() != counter_snapshot.size()) {
            return false;
        }
        if (!counter_unchanged(counter, counter_snapshot, info.is_v6 ? monitored_v6_msgs : monitored_msgs, info.is_v6 ? monitored_v6_msg_cnt : monitored_msg_cnt)) {
            return false;
        }
    }
    return true;
}

sock_info_t& sock_mgr_get_sock_info(int sock)
{
    return sock_map.at(sock);
}

void sock_mgr_init_cache_counters(const std::string &ifname, uint8_t dhcp_message_type_count, uint8_t dhcpv6_message_type_count)
{
    syslog_debug(LOG_INFO, "Initialize cache counters for interface %s to be all 0", ifname.c_str());
    
    for (auto &[sock, info] : sock_map) {
        uint8_t message_type_count = info.is_v6 ? dhcpv6_message_type_count : dhcp_message_type_count;
        for (int i = 0; i < message_type_count; i++) {
            info.all_counters[ifname][i] = 0;
        }
        info.all_counters_snapshot[ifname] = info.all_counters[ifname];
    }
}

bool sock_mgr_all_cache_counters_initialized(const std::string &ifname)
{
    for (const auto &[sock, info] : sock_map) {
        auto itr = info.all_counters.find(ifname);
        if (itr == info.all_counters.end()) {
            return false;
        }
    }
    return true;
}

void sock_mgr_update_db_counters()
{
    syslog_debug(LOG_INFO, "Updating all cache counters to DB counters");

    for (const auto &[sock, info] : sock_map) {
        syslog_debug(LOG_INFO, "Start updating socket %d %s DB counter from cache counter", sock, info.name);
        int msg_type_count = info.is_v6 ? DHCPV6_MESSAGE_TYPE_COUNT : DHCP_MESSAGE_TYPE_COUNT;
        const std::string *msg_type_name = info.is_v6 ? db_counter_name_v6 : db_counter_name;
        std::string all_ifname;
        std::string all_skipped_ifname;
        for (const auto &[ifname, counter] : info.all_counters) {
            if (is_agg_counter(ifname) == true) {
                all_skipped_ifname += ifname + ", ";
                continue;
            }
            all_ifname += ifname + ", ";
            std::string value = generate_json_string(&counter, msg_type_count, msg_type_name);
            std::string table_name = construct_counter_db_table_key(ifname, info.is_v6);
            mCountersDbPtr->hset(table_name, info.is_rx ? "RX" : "TX", value);
        }
        syslog_debug(LOG_INFO, "Processing cache counter entry of %sfor downstream vlan %s",
                     all_ifname.c_str(), downstream_ifname.c_str());
        syslog_debug(LOG_INFO, "Skipped aggregated device counter entry of %sfor downstream vlan %s",
                     all_skipped_ifname.c_str(), downstream_ifname.c_str());
    }
}