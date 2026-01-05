/**
 * @file dhcp_mon.c
 *
 * @brief dhcp relay monitor module
 */

#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <assert.h>
#include <chrono>
#include <event2/thread.h>
#include <mutex>

#include "dhcp_mon.h"

#include "dhcp_devman.h"    /** devman init/free and print */
#include "sock_mgr.h"       /** for counter operations and socket management */
#include "dhcp_device.h"    /** dhcp msg macro and health check */
#include "event_mgr.h"
#include "health_check.h"
#include "util.h"
#include <swss/events.h>
#include <swss/subscriberstatetable.h>

#define MINIMUM_BUFFER_SZ 2024

/** libevent mgr struct */
static struct event_mgr *main_event_mgr;
/** window_interval_sec monitoring window for dhcp relay health checks */
static int db_update_interval_sec;
/**
 *  When clearing counter is invoked, dhcpmon wouldn't write cache counter to COUNTERS_DB until it receives a signal,
 *  in case recover signal is not sent by cli, add timeout here. After timeout, dhcpmon would update COUNTERS_DB as before.
 */
static int clear_counter_timeout = 5;
static constexpr int MINIMAL_CLEAR_COUNTER_TIMEOUT_SEC = 5;
static constexpr int CLEAR_COUNTER_DELAY_AFTER_DB_UPDATE_SEC = 1;
/** Mutex lock to modify write_counter_to_db for different threads */
static std::mutex db_sync_mutex;
/** tag for db_update event */
static const char db_update_tag[] = "DB_UPDATE";
/** Latest timestamp of writing cache counter to COUNTERS_DB */
static std::chrono::steady_clock::time_point last_update_time{};
/** Default time point to check whether a time_point has been initialized or updated yet. */
static const std::chrono::steady_clock::time_point default_time_point{};

std::shared_ptr<swss::DBConnector> mConfigDbPtr = std::make_shared<swss::DBConnector> ("CONFIG_DB", 0);
std::shared_ptr<swss::DBConnector> mCountersDbPtr = std::make_shared<swss::DBConnector> ("COUNTERS_DB", 0);
std::shared_ptr<swss::DBConnector> mStateDbPtr = std::make_shared<swss::DBConnector> ("STATE_DB", 0);
std::shared_ptr<swss::Table> mStateDbMuxTablePtr = std::make_shared<swss::Table> (
    mStateDbPtr.get(), "HW_MUX_CABLE_TABLE"
);

/**
 * @code recalculate_agg_counter(all_counters);
 *
 * @brief recalculate agg counter based on current individual interface counters
 *
 * @param all_counters      all_counters_t to recalculate agg counter
 *
 * @return none
 */
static void recalculate_agg_counter(all_counters_t &all_counters)
{
    for (auto &[ifname, counter] : all_counters) {
        if (is_agg_counter(ifname)) {
            zero_out_counter(counter);
        }
    }
    for (const auto &[ifname, counter] : all_counters) {
        if (is_agg_counter(ifname) == false) {
            const dhcp_device_context_t *context = dhcp_devman_get_device_context(ifname);
            if (context == NULL) {
                syslog(LOG_WARNING, "Failed to find device context for interface %s when recalculating agg counter", ifname.c_str());
                continue;
            }
            if (mgmt_ifname == context->intf) {
                continue;
            }
            counter_t &agg_counter = all_counters.at(get_agg_counter_ifname(ifname, context->intf));
            for (const auto &[msg_type, count] : counter) {
                agg_counter[msg_type] += count;
            }
        }
    }
}

/**
 * @code                initialize_db_counters(ifname);
 * @brief               Initialize the counter in counters_db with interface name
 * @param ifname        interface name
 * @return              none
 */
static void initialize_db_counters(const std::string &ifname)
{
    std::string table_name;
    std::string init_value;

    syslog_debug(LOG_INFO, "Initialize DB counters for interface %s to be all 0", ifname.c_str());

    table_name = construct_counter_db_table_key(ifname, false);
    init_value = generate_json_string(NULL, DHCP_MESSAGE_TYPE_COUNT, db_counter_name);
    mCountersDbPtr->hset(table_name, "RX", init_value);
    mCountersDbPtr->hset(table_name, "TX", init_value);
    
    table_name = construct_counter_db_table_key(ifname, true);
    init_value = generate_json_string(NULL, DHCPV6_MESSAGE_TYPE_COUNT, db_counter_name_v6);
    mCountersDbPtr->hset(table_name, "RX", init_value);
    mCountersDbPtr->hset(table_name, "TX", init_value);
}

/**
 * @code              db_counters_initialized(ifname);
 * @brief             Check if the counter in counters_db is initialized for given interface name
 * @param ifname      interface name
 * @return            true if initialized, false otherwise
 */
static bool db_counters_initialized(const std::string &ifname)
{
    std::string table_name;
    std::string *field;

    table_name = construct_counter_db_table_key(ifname, false);
    field = mCountersDbPtr->hget(table_name, "RX").get();
    if (field == NULL || field->empty()) {
        return false;
    }
    field = mCountersDbPtr->hget(table_name, "TX").get();
    if (field == NULL || field->empty()) {
        return false;
    }

    table_name = construct_counter_db_table_key(ifname, true);
    field = mCountersDbPtr->hget(table_name, "RX").get();
    if (field == NULL || field->empty()) {
        return false;
    }
    field = mCountersDbPtr->hget(table_name, "TX").get();
    if (field == NULL || field->empty()) {
        return false;
    }

    return true;
}

/**
 * @code              initialize_all_counters(ifname, init_db);
 * @brief             Initialize both db counters (we do not for agg device) and cache counters for given interface name
 * @param ifname      interface name
 * @param init_db     whether to initialize db counters
 * @return            none
 */
static void initialize_all_counters(const std::string &ifname)
{
    syslog_debug(LOG_INFO, "Initialize DB counters for interface %s to be all 0", ifname.c_str());
    initialize_db_counters(ifname);
    sock_mgr_init_cache_counters(ifname, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);
}

/**
 * @code              all_counters_initialized(ifname);
 * @brief             Check if both db counters and cache counters are initialized for given interface name, cannot be used on agg device
 * @param ifname      interface name
 * @return            true if initialized, false otherwise
 */
static bool all_counters_initialized(const std::string &ifname)
{
    return db_counters_initialized(ifname) && sock_mgr_all_cache_counters_initialized(ifname);
}

/**
 * @code              cleanup_stale_db_counters();
 * @brief             Clean up stale counter entries in counters_db for interfaces that are no longer present
 *                    (not in intfs map)
 * @param             none
 * @return            none
 */
static void cleanup_stale_db_counters()
{
    syslog_debug(LOG_INFO, "Cleaning up stale counters in counters_db");
    std::string match_pattern = construct_counter_db_table_key(downstream_ifname, false) + COUNTERS_DB_SEPARATOR "*";
    auto keys = mCountersDbPtr->keys(match_pattern);
    for (const auto &key : keys) {
        auto [vlan, ifname] = parse_counter_table_key(key);
        if (vlan != downstream_ifname) {
            continue;
        }
        if (dhcp_devman_is_tracked_interface(ifname)) {
            continue;
        }
        syslog_debug(LOG_INFO, "Deleting stale counter entry for interface %s", ifname.c_str());
        mCountersDbPtr->del(key);
    }
}

/**
 * @code signal_callback(fd, event, arg);
 *
 * @brief signal handler for dhcpmon.
 *
 * @param fd        libevent socket
 * @param event     event triggered
 * @param arg       pointer to user provided context (libevent base)
 *
 * @return none
 */
static void signal_callback(evutil_socket_t fd, short event, void *arg)
{
    syslog(LOG_INFO, "Received signal: %s", strsignal(fd));
    
    dhcp_devman_print_all_status(DHCP_COUNTERS_CURRENT);
    dhcp_devman_print_all_status(DHCP_COUNTERS_CURRENT_V6);

    if ((fd == SIGTERM) || (fd == SIGINT)) {
        syslog(LOG_INFO, "Received signal to stop dhcpmon");
        dhcp_mon_stop();
    }
    if (fd == SIGUSR1) {
        // we need to sync cache counter from COUNTERS_DB
        syslog(LOG_INFO, "Received signal to stop writing to DB counter");
        std::lock_guard<std::mutex> lock(db_sync_mutex);
        sock_mgr_pause_write_cache_to_db();
        syslog(LOG_INFO, "Stopped writing to DB counter");
        mStateDbPtr->hset(STATE_DB_COUNTER_UPDATE_PREFIX + downstream_ifname, "pause_write_to_db", "done");
        mStateDbPtr->hset(STATE_DB_COUNTER_UPDATE_V6_PREFIX + downstream_ifname, "pause_write_to_db", "done");
        syslog(LOG_INFO, "Set pause_write_to_db done in STATE_DB");
    }
    if (fd == SIGUSR2) {
        syslog(LOG_INFO, "Received signal to sync DB counter to cache counter");
        sock_mgr_trigger_cache_counter_updater();
    }
}

/**
 * @code update_cache_counter(evutil_socket_t fd, short event, void *arg);
 *
 * @brief Callback function to update cache counter from DB counter. Db counter is directly maintained by dhcpmon and dhcpmon should be solely responsible
 * for its content. Dhcpmon is responsible for the initialization and updating of db data, and cli is supposed to only read it, or clear its content.
 * When cli does clear it, it loops over its keys and zero out its counters, meaning, the keys always remain the same. Since the clear counter could be done
 * on single interface, that would mean, first agg counter might be inconsistent and needs recalculating, and second after changing initialization process
 * so that cache counter is strictly identical to db counter (there could be untracked leftover interface in db counter in previous implementation), no legal
 * operation should result in inconsistency between db counter keys and cache counter keys, not even with vlan and portchannel mapping changes. The tracked
 * interfaces in db should in any circumstance be modified by dhcpmon only.
 *
 * @param fd        libevent socket
 * @param event     event triggered
 * @param arg       pointer to user provided context (libevent base)
 *
 * @return none
 */
static void update_cache_counter_callback(evutil_socket_t fd, short event, void *arg)
{
    int sock = *(int *)arg;
    sock_info_t &sock_info = sock_mgr_get_sock_info(sock);
    
    syslog(LOG_INFO, "Start updating %s cache counter from DB counter", sock_info.name);

    std::lock_guard<std::mutex> lock(db_sync_mutex);

    // can only sync db to cache counter and db updater is paused, otherwise its unexpected
    if (!sock_info.pause_write_cache_to_db) {
        syslog(LOG_WARNING, "Failed to update cache counter from DB counter on %s because pause_write_cache_to_db is not set", sock_info.name);
        return;
    }

    std::string match_pattern = (sock_info.is_v6 ? COUNTERS_DB_COUNTER_TABLE_V6_PREFIX : COUNTERS_DB_COUNTER_TABLE_PREFIX)
                                + downstream_ifname + "*";
    auto keys = mCountersDbPtr->keys(match_pattern);

    // Store interfaces in DB counter table
    std::unordered_set<std::string> updated_intfs;
    all_counters_t &all_counters = sock_info.all_counters;

    std::string all_ifname;
    std::string all_skipped_ifname;
    for (auto &key : keys) {
        // this vlan is used here only as identifier of dhcpmon instance in multivlan scenerio
        // this does not mean the second interface belongs to the vlan
        auto [vlan, ifname] = parse_counter_table_key(key);
        if (vlan != downstream_ifname) {
            all_skipped_ifname += "<" + ifname + "," + vlan + ">, ";
            continue;
        }
        all_ifname += "<" + ifname + "," + vlan + ">, ";

        // currently we consider our cache counter to be the source of truth, so if an interface is not in cache counter, we skip it
        // in the future we will add vlan changes detection and auto add/remove interface support, but in those cases we still consider
        // cache counter to be the source of truth, cache counter first and db counter follows. This is highly unexpected.
        auto itr = all_counters.find(ifname);
        if (itr == all_counters.end()) {
            syslog(LOG_WARNING, "Didn't find %s in cache counter, continue", ifname.c_str());
            continue;
        }
        counter_t &counter = itr->second;

        // read and parse db counter json string
        auto counter_json = mCountersDbPtr->hget(key, sock_info.is_rx ? "RX" : "TX");
        std::replace(counter_json.get()->begin(), counter_json.get()->end(),'\'', '\"');
        Json::Value root;
        bool parse_success = parse_json_str(counter_json.get(), &root);

        // read each dhcp message type count from json and update to cache counter
        const std::string *msg_type_name = sock_info.is_v6 ? db_counter_name_v6 : db_counter_name;
        int msg_type_count = sock_info.is_v6 ? DHCPV6_MESSAGE_TYPE_COUNT : DHCP_MESSAGE_TYPE_COUNT;
        for (int i = 0; i < msg_type_count; i++) {
            // in case parsing failed, default to 0
            counter[i]= 0;

            const std::string &column_name = msg_type_name[i];
            if (!parse_success) {
                syslog(LOG_WARNING, "Failed to parse %s %s count data for %s from COUNTERS_DB, set it to 0",
                       sock_info.name, column_name.c_str(), ifname.c_str());
                continue;
            }

            if (!root.isMember(column_name)) {
                syslog(LOG_WARNING, "DHCP type %s is not find in %s DB counter for %s, set it to 0", column_name.c_str(),
                       sock_info.name, ifname.c_str());
                continue;
            }

            if (!root[column_name].isString()) {
                syslog(LOG_WARNING, "Value type for %s in %s %s DB counter is not string, set it to 0", column_name.c_str(),
                       ifname.c_str(), sock_info.name);
                continue;
            }

            const std::string &str_count_val = root[column_name].asString();
            uint64_t count;
            if (!parse_uint64_from_str(str_count_val, count)) {
                syslog(LOG_WARNING, "Failed to parse %s count value from DB for %s %s, set it to 0",
                       sock_info.name, ifname.c_str(), column_name.c_str());
                continue;
            }

            counter[i] = count;
        }

        updated_intfs.insert(ifname);
    }
    syslog(LOG_INFO, "Processing DB entry of %sfor downstream vlan %s",
             all_ifname.c_str(), downstream_ifname.c_str());
    syslog(LOG_INFO, "Skipped DB entry of %sbecause we are only interested in %s",
             all_skipped_ifname.c_str(), downstream_ifname.c_str());

    // log any cache counter entry not appearing in db counter. This is highly unexpected.
    for (const auto &[ifname, _] : all_counters) {
        if (is_agg_counter(ifname) == false && updated_intfs.find(ifname) == updated_intfs.end()) {
            syslog(LOG_WARNING, "Entry %s in cache counter doesn't appear in DB counter", ifname.c_str());
            continue;
        }
    }

    // because we dont sync agg counters, to keep data consistent, we zero out all agg counter and recalculate
    recalculate_agg_counter(all_counters);

    sock_info.pause_write_cache_to_db = false;
    syslog(LOG_INFO, "Finished updating %s cache counter from DB counter, set pause to false", sock_info.name);

    const char *counter_update_prefix = sock_info.is_v6 ? STATE_DB_COUNTER_UPDATE_V6_PREFIX : STATE_DB_COUNTER_UPDATE_PREFIX;
    const std::string lower_case_dir = sock_info.is_rx ? "rx" : "tx";
    mStateDbPtr->hset(counter_update_prefix + downstream_ifname,
                      lower_case_dir + "_cache_update", "done");
    syslog(LOG_INFO, "Set %s_cache_update done in STATE_DB for %s", lower_case_dir.c_str(), sock_info.name);

    // if we have finished syncing all sockets, we trigger a update from cache counter to DB counter
    // for discrepency in interface between cache counter and DB counter, we dont handle it in this function
    // we leave it to db updater to handle it
    if (sock_mgr_pause_write_cache_to_db_all_cleared()) {
        syslog(LOG_INFO, "All sockets cleared pause_write_cache_to_db, start write back to DB counter from cache counter");
        main_event_mgr->activate_all_events(db_update_tag, EV_TIMEOUT);
    }
}

/**
 * @code timeout_callback(fd, event, arg);
 *
 * @brief periodic timer call back
 *
 * @param fd        libevent socket
 * @param event     event triggered
 * @param arg       pointer user provided context (libevent base)
 *
 * @return none
 */
static void timeout_callback(evutil_socket_t fd, short event, void *arg)
{
    syslog_debug(LOG_INFO, "Received timeout signal for DHCP relay health check");

    dhcp_devman_print_all_status_debug(DHCP_COUNTERS_CURRENT);
    dhcp_devman_print_all_status_debug(DHCP_COUNTERS_SNAPSHOT);
    dhcp_devman_print_all_status_debug(DHCP_COUNTERS_CURRENT_V6);
    dhcp_devman_print_all_status_debug(DHCP_COUNTERS_SNAPSHOT_V6);

    check_dhcp_relay_health();

    sock_mgr_update_snapshot();
}

/**
 * @code db_update_callback(fd, event, arg);
 *
 * @brief periodic timer call back
 *
 * @param fd        libevent socket
 * @param event     event triggered
 * @param arg       pointer user provided context (libevent base)
 *
 * @return none
 */
static void db_update_callback(evutil_socket_t fd, short event, void *arg)
{
    syslog_debug(LOG_INFO, "Received db update signal");
    syslog_debug(LOG_INFO, "Sync cache counter to DB counter");
    std::lock_guard<std::mutex> lock(db_sync_mutex);
    // If there is clear counter going on and its been longer than expected
    // consider the clear counter operation failed so we don't block db update forever
    if (!sock_mgr_pause_write_cache_to_db_all_cleared() && last_update_time != default_time_point) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_update_time);
        if (elapsed.count() >= clear_counter_timeout) {
            syslog(LOG_WARNING, "Clear counter going on for too long, abort clear counter");
            sock_mgr_clear_pause_write_cache_to_db();
        } else {
            syslog(LOG_INFO, "Clear counter is ongoing, skip syncing write cache counter to DB counter");
            return;
        }
    }
    last_update_time = std::chrono::steady_clock::now();
    sock_mgr_update_db_counters();
    cleanup_stale_db_counters();
    syslog_debug(LOG_INFO, "Successfully synced cache counter to DB counter");
}

/**
 * @code free_event_mgr(struct event_mgr *mgr);
 *
 * @brief Free event manager
 * 
 * @param mgr pointer to event manager
 */
static void free_event_mgr(struct event_mgr *mgr)
{
    if (mgr != NULL) {
        mgr->free();
        delete mgr;
    }
}

/**
 * @code              initialize_all_intf_counters();
 * @brief             Initialize all db counters and cache counters for all tracked interfaces
 * @param             none
 * @return            0 upon success, negative upon failure
 */
static void initialize_all_intf_counters()
{
    for (const auto &[vlan, intfs] : rev_vlan_map) {
        for (const auto &ifname : intfs) {
            initialize_all_counters(ifname);
        }
        initialize_all_counters(vlan);
        sock_mgr_init_cache_counters(agg_dev_prefix + vlan, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);
    }

    for (const auto &[portchan, intfs] : rev_portchan_map) {
        for (const auto &ifname : intfs) {
            initialize_all_counters(ifname);
        }
        initialize_all_counters(portchan);
        sock_mgr_init_cache_counters(agg_dev_prefix + portchan, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);
    }

    // Now all vlan and portchannel related interfaces have entries in counters, now do the rest (uplink)
    for (const auto &itr : intfs) {
        if (!all_counters_initialized(itr.first)) {
            initialize_all_counters(itr.first);
        }
    }

    // also initialize mgmt and agg device counters
    if (mgmt_ifname.size() > 0) {
        initialize_all_counters(mgmt_ifname);
    }

    sock_mgr_init_cache_counters(agg_dev_all, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);

    // counter db (the interfaces) might be outdated, clean up stale entries to be in sync with current tracked interfaces
    cleanup_stale_db_counters();
}

int dhcp_mon_init(size_t snaplen, int window_sec, int max_count, int db_update_interval)
{
    int rv = -1;

    syslog(LOG_INFO, "Initializing dhcp monitor with snaplen %zu, window_sec %d, max_count %d, db_update_interval %d",
           snaplen, window_sec, max_count, db_update_interval);

    if (snaplen < MINIMUM_BUFFER_SZ) {
        syslog(LOG_ALERT, "Snap length is too low to capture DHCP options, snaplen: %zu, minimum required: %d", snaplen, MINIMUM_BUFFER_SZ);
        goto no_free;
    }

    if (dhcp_devman_init() < 0) {
        syslog(LOG_ALERT, "Failed to initialize dhcp device manager");
        goto no_free;
    }

    if (sock_mgr_init(snaplen) < 0) {
        syslog(LOG_ALERT, "Failed to initialize sock_map");
        goto free_devman;
    }

    // deinitialization of counters is not our responsibility
    // cache counter will be cleanup by sock_mgr_free and the initialized db we intend to keep
    initialize_all_intf_counters();
    syslog(LOG_INFO, "Initialized all counters for tracked interfaces");

    window_interval_sec = window_sec;
    dhcp_unhealthy_max_count = max_count;
    db_update_interval_sec = db_update_interval;

    // Set clear_counter_timeout based on db_update_interval
    if (db_update_interval < MINIMAL_CLEAR_COUNTER_TIMEOUT_SEC - CLEAR_COUNTER_DELAY_AFTER_DB_UPDATE_SEC) {
        clear_counter_timeout = MINIMAL_CLEAR_COUNTER_TIMEOUT_SEC;
    } else {
        clear_counter_timeout = db_update_interval + CLEAR_COUNTER_DELAY_AFTER_DB_UPDATE_SEC ;
    }
    syslog(LOG_INFO, "clear_counter_timeout is set to %is", clear_counter_timeout);

    // enable libevent thread safety
    evthread_use_pthreads();

    main_event_mgr = new event_mgr("MAIN");
    if (main_event_mgr->init_base() < 0) {
        syslog(LOG_ALERT, "Failed to initialize main event manager");
        goto free_sock_mgr;
    }

    if (sock_mgr_init_event_mgr() < 0) {
        syslog(LOG_ALERT, "Failed to initialize event managers for sock mgr");
        goto free_main_event_mgr;
    }

    g_events_handle = events_init_publisher("sonic-events-dhcp-relay");
    if (g_events_handle == NULL) {
        syslog(LOG_ALERT, "Failed to initialize events publisher");
        goto free_sock_mgr_event_mgr;
    }

    rv = 0;

    syslog(LOG_INFO, "Dhcp monitor initialized successfully");

    return rv;

free_sock_mgr_event_mgr:
    sock_mgr_free_event_mgr();
free_main_event_mgr:
    free_event_mgr(main_event_mgr);
free_sock_mgr:
    sock_mgr_free();
free_devman:
    dhcp_devman_free();
no_free:
    return rv;
}

/**
 * @code dhcp_mon_free();
 *
 * @brief frees resources used by dhcp monitor
 */
void dhcp_mon_free()
{
    events_deinit_publisher(g_events_handle);
    sock_mgr_free_event_mgr();
    free_event_mgr(main_event_mgr);
    sock_mgr_free();
    dhcp_devman_free();
}

/**
 * @code              register_main_events();
 * @brief             Register main events including signal and periodic timer events
 * @param none        none
 * @return            0 upon success, negative upon failure
 */
static int register_main_events()
{
    int rv = -1;

    do {
        syslog(LOG_INFO, "Registering main events");

        struct event *ev_sigint = evsignal_new(main_event_mgr->get_base(), SIGINT, signal_callback, main_event_mgr->get_base());
        if (ev_sigint == NULL) {
            syslog(LOG_ALERT, "Could not create SIGINT libevent signal!");
            break;
        }
        if (main_event_mgr->add_event(ev_sigint, NULL) < 0) {
            syslog(LOG_ALERT, "Failed to add SIGINT event for main thread");
            event_free(ev_sigint);
            break;
        }

        struct event *ev_sigterm = evsignal_new(main_event_mgr->get_base(), SIGTERM, signal_callback, main_event_mgr->get_base());
        if (ev_sigterm == NULL) {
            syslog(LOG_ALERT, "Could not create SIGTERM libevent signal!");
            break;
        }
        if (main_event_mgr->add_event(ev_sigterm, NULL) < 0) {
            syslog(LOG_ALERT, "Failed to add SIGTERM event for main thread");
            event_free(ev_sigterm);
            break;
        }

        struct event *ev_sigusr1 = evsignal_new(main_event_mgr->get_base(), SIGUSR1, signal_callback, main_event_mgr->get_base());
        if (ev_sigusr1 == NULL) {
            syslog(LOG_ALERT, "Could not create SIGUSER1 libevent signal!");
            break;
        }
        if (main_event_mgr->add_event(ev_sigusr1, NULL) < 0) {
            syslog(LOG_ALERT, "Failed to add SIGUSR1 event for main thread");
            event_free(ev_sigusr1);
            break;
        }

        struct event *ev_sigusr2 = evsignal_new(main_event_mgr->get_base(), SIGUSR2, signal_callback, main_event_mgr->get_base());
        if (ev_sigusr2 == NULL) {
            syslog(LOG_ALERT, "Could not create SIGUSR2 libevent signal!");
            break;
        }
        if (main_event_mgr->add_event(ev_sigusr2, NULL) < 0) {
            syslog(LOG_ALERT, "Failed to add SIGUSR2 event for main thread");
            event_free(ev_sigusr2);
            break;
        }

        struct timeval event_time = {.tv_sec = window_interval_sec, .tv_usec = 0};
        struct event *ev_timeout = event_new(main_event_mgr->get_base(), -1, EV_PERSIST, timeout_callback, main_event_mgr->get_base());
        if (ev_timeout == NULL) {
            syslog(LOG_ALERT, "Could not create libevent timer!");
            break;
        }
        if (main_event_mgr->add_event(ev_timeout, &event_time) < 0) {
            syslog(LOG_ALERT, "Failed to add timeout event for main thread");
            event_free(ev_timeout);
            break;
        }

        struct timeval db_update_event_time = {.tv_sec = db_update_interval_sec, .tv_usec = 0};
        struct event *ev_db_update = event_new(main_event_mgr->get_base(), -1, EV_PERSIST, db_update_callback, main_event_mgr->get_base());
        if (ev_db_update == NULL) {
            syslog(LOG_ALERT, "Could not create db update timer!");
            break;
        }
        if (main_event_mgr->add_event(ev_db_update, &db_update_event_time, db_update_tag) < 0) {
            syslog(LOG_ALERT, "Failed to add db_update event for main thread");
            event_free(ev_db_update);
            break;
        }

        rv = 0;

        syslog(LOG_INFO, "Main events registered successfully");

        return rv;

    } while (0);

    main_event_mgr->del_all_events();

    return rv;
}

/**
 * @code dhcp_mon_start();
 *
 * @brief the function is long running and not supposed to return until dhcp_mon_stop is called, it takes care of
 *        cleanup by itself when it returns
 *
 * @param none
 *
 * @return 0 upon success, negative upon failure
 */
int dhcp_mon_start()
{
    int rv = -1;

    syslog(LOG_INFO, "Starting dhcp monitor in %s", debug_on ? "debug mode" : "normal mode");

    if (sock_mgr_register_packet_handler() < 0) {
        syslog(LOG_ALERT, "Failed to start socket manager packet handler");
        goto no_cleanup;
    }

    if (sock_mgr_register_cache_counter_updater(update_cache_counter_callback) < 0) {
        syslog(LOG_ALERT, "Failed to start cache counter updater");
        goto unregister_packet_handler;
    }

    if (register_main_events() < 0) {
        syslog(LOG_ALERT, "Failed to start main event loop");
        goto unregister_cache_counter_updater;
    }

    sock_mgr_drain_sock_buffer();

    // it could fail and we wouldnt know it because its in another thread
    sock_mgr_start_event_loop();

    if (event_base_dispatch(main_event_mgr->get_base()) < 0) {
        syslog(LOG_ALERT, "Could not start libevent dispatching loop!");
        sock_mgr_stop_event_loop();
        goto wait_sock_mgr_event_loop;
    }

    rv = 0;

    syslog(LOG_INFO, "Dhcp monitor was running successfully and now it is terminating successfully");

wait_sock_mgr_event_loop:
    sock_mgr_wait_event_loop();
unregister_main_events:
    main_event_mgr->del_all_events();
unregister_cache_counter_updater:
    sock_mgr_unregister_cache_counter_updater();
unregister_packet_handler:
    sock_mgr_unregister_packet_handler();
no_cleanup:
    return rv;
}

/**
 * @code dhcp_mon_stop();
 *
 * @brief since dhcp_mon_start is supposed to be long running, dhcp_mon_stop is not designed to run after
 * dhcp_mon_start finishs, but run concurrently with dhcp_run_start. The function stops dhcpmon main loop
 * and sock_mgr loop, the rest of the cleanup will be done in dhcp_mon_start itself.
 */
void dhcp_mon_stop()
{
    syslog(LOG_INFO, "Stopping dhcp monitor");
    sock_mgr_stop_event_loop();
    event_base_loopexit(main_event_mgr->get_base(), NULL);
    syslog(LOG_INFO, "Stopped dhcp monitor event loops");
}
