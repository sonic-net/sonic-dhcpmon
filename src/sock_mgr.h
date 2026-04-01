/**
 * @file socket_manager.h
 *
 *  Manages the opened raw sockets and its related counters and buffers. Includes operations on all sock (like init/free)
 *  and a getter function.
 *  Functions are noop on failure.
 */

#ifndef SOCKET_MANAGER_H_
#define SOCKET_MANAGER_H_

#include <stdint.h>
#include <string>
#include <unordered_map>
#include <linux/filter.h>
#include <thread>

#include "event_mgr.h"

typedef std::unordered_map<uint8_t, uint64_t> counter_t;
typedef std::unordered_map<std::string, counter_t> all_counters_t;

/** struct for socket information */
typedef struct {
    int sock;
    const char *name;
    bool is_rx;
    bool is_v6;
    uint8_t *buffer;
    size_t snaplen;
    const char *filter;
    struct sock_fprog bpf_prog;
    all_counters_t all_counters;
    all_counters_t all_counters_snapshot;
    bool pause_write_cache_to_db;
    void *packet_handler;
    event_mgr *event_mgr_ptr;
    std::thread event_thread;
} sock_info_t;

/** sock file descriptors, serve as the identifier of all related information described in sock_info_t */
extern int rx_sock, tx_sock, rx_sock_v6, tx_sock_v6;

/** Initialize socket manager with given snaplen */
int sock_mgr_init(uint32_t snaplen);

/** Free all resources allocated by socket manager */
void sock_mgr_free();

/** Initialize event manager for socket manager */
int sock_mgr_init_event_mgr();

/** Free event manager resources for socket manager */
void sock_mgr_free_event_mgr();

/** Register packet handler for socket manager as defined in packet_handler.h */
int sock_mgr_register_packet_handler();

/** Unregister packet handler for socket manager */
void sock_mgr_unregister_packet_handler();

/** Register cache counter updater callback for socket manager */
int sock_mgr_register_cache_counter_updater(event_callback_fn callback);

/** Unregister cache counter updater callback for socket manager */
void sock_mgr_unregister_cache_counter_updater();

/** Pause writing cache counters to database */
void sock_mgr_pause_write_cache_to_db();

/** Clear pause writing cache counters to database */
void sock_mgr_clear_pause_write_cache_to_db();

/** Check if pause writing cache counters to database is cleared for all */
bool sock_mgr_pause_write_cache_to_db_all_cleared();

/** Trigger cache counter updater */
void sock_mgr_trigger_cache_counter_updater();

/** Drain all unfiltered packets from all sockets, should do that prior to reading from sockets */
void sock_mgr_drain_sock_buffer();

/** Start the all event loops for socket manager */
void sock_mgr_start_event_loop();

/** Wait for all event loops to end for socket manager */
void sock_mgr_wait_event_loop();

/** Stop all event loops for socket manager */
void sock_mgr_stop_event_loop();

/** Update snapshot counters for all sockets */
void sock_mgr_update_snapshot();

/** Check if counters are unchanged for given ifname and monitored message types */
bool sock_mgr_counters_unchanged(const std::string &ifname, const int *monitored_msgs, size_t monitored_msg_cnt, const int *monitored_v6_msgs, size_t monitored_v6_msg_cnt);

/** Get socket info struct for given socket, in the event of extremely unexpected nonexistent socket, just fail */
sock_info_t& sock_mgr_get_sock_info(int sock);

/** Initialize cache counters for given ifname for all sockets */
void sock_mgr_init_cache_counters(const std::string &ifname, uint8_t dhcp_message_type_count, uint8_t dhcpv6_message_type_count);

/** Check if cache counters are initialized for given ifname for all sockets */
bool sock_mgr_all_cache_counters_initialized(const std::string &ifname);

/** Update database counters from cache counters for all sockets */
void sock_mgr_update_db_counters();

#endif /* SOCKET_MANAGER_H_ */
