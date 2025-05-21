/**
 * @file dhcp_mon.c
 *
 *  @brief dhcp relay monitor module
 */

#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <assert.h>
#include <chrono>

#include "dhcp_mon.h"
#include "dhcp_devman.h"
#include "event_mgr.h"
#include "events.h"

/** DHCP device/interface state */
typedef struct
{
    dhcp_mon_check_t check_type;                /** check type */
    dhcp_device_context_t* (*get_context)();    /** functor to a device context accessor function */
    int count;                                  /** count in the number of unhealthy checks */
    const char *msg;                            /** message to be printed if unhealthy state is determined */
} dhcp_mon_state_t;

/** window_interval_sec monitoring window for dhcp relay health checks */
static int window_interval_sec = 18;
/** dhcp_unhealthy_max_count max count of consecutive unhealthy statuses before reporting to syslog */
static int dhcp_unhealthy_max_count = 10;
/** dhcpmon debug mode control flag */
static bool debug_on = false;
/** libevent mgr struct */
static struct event_mgr *main_event_mgr = NULL;
/** libevent mgr struct */
static struct event_mgr *rx_event_mgr = NULL;
/** libevent mgr struct */
static struct event_mgr *tx_event_mgr = NULL;
/** event to sync RX cache counter from COUNTERS_DB */
struct event *ev_rx_cache_counter_update = NULL;
/** event to sync RX cache counter from COUNTERS_DB */
struct event *ev_tx_cache_counter_update = NULL;
/** event to write COUNTERS_DB */
struct event *ev_db_update = NULL;
/** Indicate whether is diff between counters_db and cache */
static bool cache_db_diff = false;
/** window_interval_sec monitoring window for dhcp relay health checks */
static int db_update_interval_sec;
/** When clearing counter is invoked, dhcpmon wouldn't write cache counter to COUNTERS_DB until it receives a signal,
 *  in case recover signal is not sent by cli, add timeout 5s here. After 5s, dhcpmon would update COUNTERS_DB as previous.
 */
static constexpr int clear_counter_timeout = 5;
/** Flag to determine whether to write cache counter to COUNTERS_DB.
 *  0b11 - write (rx and tx cache counter are both up to date)
 *  0b00 - don't write (Need to sync rx and tx cache counter from COUNTERS_DB)
 *  0b01 - don't write (rx cache counter is up to date, but need to sync tx cache counter from COUNTERS_DB)
 *  0b10 - don't write (tx cache counter is up to date, but need to sync rx cache counter from COUNTERS_DB) */
static constexpr int rx_cache_updated = 0b01;
static constexpr int tx_cache_updated = 0b10;
static int write_counter_to_db = rx_cache_updated | tx_cache_updated;
/** Mutex lock to moidfy write_counter_to_db for different threads */
static std::mutex write_counter_mutex;
/** Latest timestamp of writing cache counter to COUNTERS_DB */
static std::chrono::steady_clock::time_point last_update_time{};
/** Default time point to check whether a time_point has been initialized or updated yet. */
static const std::chrono::steady_clock::time_point default_time_point{};

event_handle_t g_events_handle;

/** DHCP monitor state data for aggregate device for mgmt device */
static dhcp_mon_state_t state_data[] = {
    [0] = {
        .check_type = DHCP_MON_CHECK_POSITIVE,
        .get_context = dhcp_devman_get_agg_dev,
        .count = 0,
        .msg = "dhcpmon detected disparity in DHCP Relay behavior. Duration: %d (sec) for vlan: '%s'\n"
    },
    [1] = {
        .check_type = DHCP_MON_CHECK_NEGATIVE,
        .get_context = dhcp_devman_get_mgmt_dev,
        .count = 0,
        .msg = "dhcpmon detected DHCP packets traveling through mgmt interface (please check BGP routes.)"
               " Duration: %d (sec) for intf: '%s'\n"
    }
};

/**
 * @code signal_callback(fd, event, arg);
 *
 * @brief signal handler for dhcpmon. It will initiate shutdown when signal is caught
 *
 * @param fd        libevent socket
 * @param event     event triggered
 * @param arg       pointer to user provided context (libevent base)
 *
 * @return none
 */
static void signal_callback(evutil_socket_t fd, short event, void *arg)
{
    syslog(LOG_ALERT, "Received signal: '%s'\n", strsignal(fd));
    dhcp_devman_print_status(NULL, DHCP_COUNTERS_CURRENT);
    if ((fd == SIGTERM) || (fd == SIGINT)) {
        dhcp_mon_stop();
    }
    if (fd == SIGUSR1) {
        // Set write_counter_to_db to 0 to make sure dhcpmon wouldn't write counter data to COUNTERS_DB because
        // we need to sync cache counter from COUNTERS_DB
        syslog(LOG_INFO, "Received signal to stop writing DB counter\n");
        std::lock_guard<std::mutex> lock(write_counter_mutex);
        write_counter_to_db = 0b00;
        mStateDbPtr->hset(STATE_DB_COUNTER_UPDATE_PREFIX + downstream_if_name, "pause_write_to_db", "done");
        syslog(LOG_INFO, "Stopped writing DB counter\n");
    }
    if (fd == SIGUSR2) {
        event_active(ev_rx_cache_counter_update, 0, 0);
        event_active(ev_tx_cache_counter_update, 0, 0);
    }
}

/**
 * @code update_cache_counter(evutil_socket_t fd, short event, void *arg);
 *
 * @brief Callback function to update cache counter from DB counter.
 *
 * @param fd        libevent socket
 * @param event     event triggered
 * @param arg       pointer to user provided context (libevent base)
 *
 * @return none
 */
static void update_cache_counter(evutil_socket_t fd, short event, void *arg) {
    if (write_counter_to_db != 0b00) {
        syslog(LOG_ERR, "Write DB counter from cache counter hasn't stop, cannot sync cache counter from DB counter\n");
        return;
    }
    dhcp_packet_direction_t* dir_ptr = reinterpret_cast<dhcp_packet_direction_t*>(arg);
    dhcp_packet_direction_t dir = *dir_ptr;
    std::string dir_str = gen_dir_str(dir, UPPER_CASE);

    syslog(LOG_INFO, "Update %s cache counter\n", dir_str.c_str());

    auto match_pattern = COUNTERS_DB_COUNTER_TABLE_PREFIX + downstream_if_name + "*";
    std::lock_guard<std::mutex> lock(write_counter_mutex);
    auto keys = mCountersDbPtr->keys(match_pattern);

    // Store interfaces in DB counter table
    std::unordered_set<std::string> updated_intfs;

    auto counter_map = dhcp_device_get_counter(dir);
    for (auto &itr : keys) {
        std::string interface;
        std::string vlan;
        parse_counter_table_key(itr, vlan, interface);

        if (vlan.compare(downstream_if_name) != 0) {
            syslog(LOG_INFO, "Skip [%s - %s] since it's not related to current downstream interface\n", vlan.c_str(), interface.c_str());
            continue;
        }

        auto interface_key = construct_counter_db_table_key(interface);
        auto counter_json = mCountersDbPtr->hget(interface_key, dir_str);
        std::replace(counter_json.get()->begin(), counter_json.get()->end(),'\'', '\"');
        Json::Value root;
        bool parse_result = parse_json_str(counter_json.get(), &root);

        auto counter = counter_map->find(interface);
        if (counter == counter_map->end()) {
            // Didn't have this interface in counter map, re-init it
            syslog(LOG_INFO, "Didn't find %s in cache counter, init it now\n", interface.c_str());
            initialize_cache_counter(*counter_map, interface);
        }

        for (int i = 0; i < DHCP_MESSAGE_TYPE_COUNT; i++) {
            const auto& type = db_counter_name[i];
            uint64_t count;
            if (!parse_result) {
                // If fail to parse from counters_db, set it to be zero
                syslog(LOG_WARNING, "Failed to parse %s %s count data for %s from COUNTERS_DB, set it to 0\n",
                       dir_str.c_str(), type.c_str(), interface.c_str());
                count = 0;
                cache_db_diff = true;
            } else {
                // If [corresponding DB counter doesn't exist] or [failed to parse count value], set it to 0.
                // Else, set it to value parsed.
                if (!root.isMember(type)) {
                    syslog(LOG_WARNING, "DHCP type %s is not find in %s DB counter for %s, set it to 0\n", type.c_str(),
                           dir_str.c_str(), interface.c_str());
                    count = 0;
                    cache_db_diff = true;
                } else if (!root[type].isString()) {
                    syslog(LOG_WARNING, "Value type for %s in %s %s DB counter is not string, set it to 0\n", type.c_str(),
                           interface.c_str(), dir_str.c_str());
                    count = 0;
                    cache_db_diff = true;
                } else {
                    std::string str_count_val = root[type].asString();
                    if (!parse_uint64_from_str(str_count_val, count)) {
                        syslog(LOG_WARNING, "Failed to parse %s count value from DB for %s %s, set it to 0\n",
                               dir_str.c_str(), interface.c_str(), type.c_str());
                        count = 0;
                        cache_db_diff = true;
                    }
                }
            }
            (*counter_map)[interface][i] = count;
            syslog(LOG_INFO, "Sync %s cache counter for %s %s to %lu\n", dir_str.c_str(), interface.c_str(), type.c_str(), count);
        }
        updated_intfs.insert(interface);
    }

    // Loop cache counter map, delete counter that doesn't appear in DB counter
    for (auto it = counter_map->begin(); it != counter_map->end();) {
        if (updated_intfs.find(it->first) == updated_intfs.end()) {
            // Not such interface in DB counter, need to delete from cache counter
            syslog(LOG_INFO, "Remove %s in cache counter since it doesn't appear in DB counter\n", it->first.c_str());
            it = counter_map->erase(it);
        } else {
            ++it;
        }
    }

    // Update write_counter_to_db. If RX updated, the last bit is set to 1; if TX updated, the first bit is set to 1;
    int dir_value = static_cast<int>(dir);
    write_counter_to_db |= (1 << dir_value);

    mStateDbPtr->hset(STATE_DB_COUNTER_UPDATE_PREFIX + downstream_if_name,
                      gen_dir_str(dir, LOWER_CASE) + "_cache_update", "done");
    syslog(LOG_INFO, "Update %s cache counter done", dir_str.c_str());
    if (cache_db_diff && write_counter_to_db == (rx_cache_updated | tx_cache_updated)) {
        syslog(LOG_INFO, "%s COUNTERS_DB and cache counter have diff, write cache counter to COUNTERS_DB immediately\n",
               dir_str.c_str()); 
        event_active(ev_db_update, EV_TIMEOUT, 0);
    }
}

/**
 * @code check_dhcp_relay_health(state_data);
 *
 * @brief check DHCP relay overall health
 *
 * @param state_data        pointer to dhcpmon state data
 *
 * @return none
 */
static void check_dhcp_relay_health(dhcp_mon_state_t *state_data)
{
    dhcp_device_context_t *context = state_data->get_context();
    dhcp_mon_status_t dhcp_mon_status = dhcp_devman_get_status(state_data->check_type, context);

    switch (dhcp_mon_status)
    {
    case DHCP_MON_STATUS_UNHEALTHY:
        if (++state_data->count > dhcp_unhealthy_max_count) {
            auto duration = state_data->count * window_interval_sec;
            std::string vlan(context->intf);
            syslog(LOG_ALERT, state_data->msg, duration, context->intf);
            if (state_data->check_type == DHCP_MON_CHECK_POSITIVE) {
                event_params_t params = {
                    { "vlan", vlan },
                    { "duration", std::to_string(duration) }};
                event_publish(g_events_handle, "dhcp-relay-disparity", &params);
            }
            dhcp_devman_print_status(context, DHCP_COUNTERS_SNAPSHOT);
            dhcp_devman_print_status(context, DHCP_COUNTERS_CURRENT);
        }
        break;
    case DHCP_MON_STATUS_HEALTHY:
        state_data->count = 0;
        break;
    case DHCP_MON_STATUS_INDETERMINATE:
        if (state_data->count) {
            state_data->count++;
        }
        break;
    default:
        syslog(LOG_ERR, "DHCP Relay returned unknown status %d\n", dhcp_mon_status);
        break;
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
    for (uint8_t i = 0; i < sizeof(state_data) / sizeof(*state_data); i++) {
        check_dhcp_relay_health(&state_data[i]);
    }

    dhcp_devman_update_snapshot(NULL);

    if (debug_on) {
        dhcp_devman_print_status(NULL, DHCP_COUNTERS_SNAPSHOT);
        dhcp_devman_print_status(NULL, DHCP_COUNTERS_CURRENT);
    }
}

/**
 * @code update_counter(dhcp_packet_direction_t dir)
 * @brief Function to update counter in COUNTERS_DB
 * @param dir       Packet direction
 * @return none
 */
void update_counter(dhcp_packet_direction_t dir) {
    std::unordered_map<std::string, std::unordered_map<uint8_t, uint64_t>>* counter = dhcp_device_get_counter(dir);
    for (const auto& outer_pair : *counter) {
        const std::string interface_name = outer_pair.first;
        const auto* inner_map = &outer_pair.second;
        std::string value = generate_json_string(inner_map);
        /**
         * Only add downstream prefix for non-downstream interface
         */
        std::string table_name = construct_counter_db_table_key(interface_name);
        mCountersDbPtr->hset(table_name, gen_dir_str(dir, UPPER_CASE), value);
    }
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
    syslog(LOG_INFO, "Start to write DB counter\n");
    std::lock_guard<std::mutex> lock(write_counter_mutex);
    // If write_counter_to_db == 0b11, means that there is no clear counter ongoing, we can directly update DB counter from cache counter.
    // Else, we cannot write DB counter except pause time timeout.
    if (write_counter_to_db != 0b11 && last_update_time != default_time_point) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_update_time);
        if (elapsed.count() >= clear_counter_timeout) {
            syslog(LOG_ALERT, "Timeout for lock writing to DB\n");
            write_counter_to_db = 0b11;
        } else {
            syslog(LOG_INFO, "Clear counter is ongoing, skip write counter to DB\n");
            return;
        }
    }
    last_update_time = std::chrono::steady_clock::now();
    update_counter(DHCP_RX);
    update_counter(DHCP_TX);
    syslog(LOG_INFO, "Write DB counter done\n");
}

/**
 * @code dhcp_mon_init(window_sec, max_count, dbu_update_interval);
 *
 * initializes event base and periodic timer event that continuously collects dhcp relay health status every window_sec
 * seconds. It also writes to syslog when dhcp relay has been unhealthy for consecutive max_count checks.
 *
 */
int dhcp_mon_init(int window_sec, int max_count, int db_update_interval)
{
    int rv = -1;

    do {
        window_interval_sec = window_sec;
        dhcp_unhealthy_max_count = max_count;
        db_update_interval_sec = db_update_interval;

        if (main_event_mgr != NULL || rx_event_mgr != NULL || tx_event_mgr != NULL) {
            syslog(LOG_ERR, "Duplicated invoking of dhcp_mon_init, cannot determine whether mgr obj is expected\n");
            break;
        }
        evthread_use_pthreads();

        main_event_mgr = new event_mgr("MAIN");
        if (main_event_mgr->init_base() != 0)
            break;

        rx_event_mgr = new event_mgr("RX_PACKET");
        if (rx_event_mgr->init_base() != 0)
            break;

        tx_event_mgr = new event_mgr("TX_PACKET");
        if (tx_event_mgr->init_base() != 0)
            break;

        g_events_handle = events_init_publisher("sonic-events-dhcp-relay");

        rv = 0;
    } while (0);

    return rv;
}

/**
 * @code free_event_mgr(struct event_mgr *mgr);
 *
 * @brief Free event manager
 * 
 * @param mgr pointer to event manager
 */
void free_event_mgr(struct event_mgr *mgr) {
    if (mgr != NULL) {
        mgr -> free();
        delete mgr;
    }
}

/**
 * @code dhcp_mon_shutdown();
 *
 * @brief shuts down libevent loop
 */
void dhcp_mon_shutdown()
{
    free_event_mgr(rx_event_mgr);
    free_event_mgr(tx_event_mgr);
    free_event_mgr(main_event_mgr);

    events_deinit_publisher(g_events_handle);
}

/**
 * @code rx_sub_thread_dispatch();
 * 
 * @brief dispatch rx event
 */
void rx_sub_thread_dispatch() {
    if (event_base_dispatch(rx_event_mgr->get_base()) != 0) {
        syslog(LOG_ERR, "Could not start rx packet libevent dispatching loop!\n");
    }
}

/**
 * @code tx_sub_thread_dispatch();
 * 
 * @brief dispatch tx event
 */
void tx_sub_thread_dispatch() {
    if (event_base_dispatch(tx_event_mgr->get_base()) != 0) {
        syslog(LOG_ERR, "Could not start tx packet libevent dispatching loop!\n");
    }
}

/**
 * @code dhcp_mon_start(snaplen, debug_mode);
 *
 * @brief start monitoring DHCP Relay
 */
int dhcp_mon_start(size_t snaplen, bool debug_mode)
{
    int rv = -1;
    debug_on = debug_mode;

    do
    {
        if (dhcp_devman_start_capture(snaplen, rx_event_mgr, tx_event_mgr) != 0) {
            break;
        }

        struct event *ev_sigint = evsignal_new(main_event_mgr->get_base(), SIGINT, signal_callback, main_event_mgr->get_base());
        if (ev_sigint == NULL) {
            syslog(LOG_ERR, "Could not create SIGINT libevent signal!\n");
            break;
        }

        struct event *ev_sigterm = evsignal_new(main_event_mgr->get_base(), SIGTERM, signal_callback, main_event_mgr->get_base());
        if (ev_sigterm == NULL) {
            syslog(LOG_ERR, "Could not create SIGTERM libevent signal!\n");
            break;
        }

        struct event *ev_sigusr1 = evsignal_new(main_event_mgr->get_base(), SIGUSR1, signal_callback, main_event_mgr->get_base());
        if (ev_sigusr1 == NULL) {
            syslog(LOG_ERR, "Could not create SIGUSER1 libevent signal!\n");
            break;
        }

        struct event *ev_sigusr2 = evsignal_new(main_event_mgr->get_base(), SIGUSR2, signal_callback, main_event_mgr->get_base());
        if (ev_sigusr2 == NULL) {
            syslog(LOG_ERR, "Could not create SIGUSR2 libevent signal!\n");
            break;
        }

    
        cache_db_diff = false;
        dhcp_packet_direction_t temp_dir_rx = DHCP_RX;
        event_init_check_and_free(ev_rx_cache_counter_update);
        ev_rx_cache_counter_update = event_new(rx_event_mgr->get_base(), -1, 0, update_cache_counter, reinterpret_cast<void*>(&temp_dir_rx));
        dhcp_packet_direction_t temp_dir_tx = DHCP_TX;
        event_init_check_and_free(ev_tx_cache_counter_update);
        ev_tx_cache_counter_update = event_new(tx_event_mgr->get_base(), -1, 0, update_cache_counter, reinterpret_cast<void*>(&temp_dir_tx));

        struct event *ev_timeout = event_new(main_event_mgr->get_base(), -1, EV_PERSIST, timeout_callback, main_event_mgr->get_base());
        if (ev_timeout == NULL) {
            syslog(LOG_ERR, "Could not create libevent timer!\n");
            break;
        }

        event_init_check_and_free(ev_db_update);
        ev_db_update = event_new(main_event_mgr->get_base(), -1, EV_PERSIST, db_update_callback, main_event_mgr->get_base());
        if (ev_db_update == NULL) {
            syslog(LOG_ERR, "Could not create db update timer!\n");
            break;
        }

        struct timeval event_time = {.tv_sec = window_interval_sec, .tv_usec = 0};
        struct timeval db_update_event_time = {.tv_sec = db_update_interval_sec, .tv_usec = 0};

        if (main_event_mgr->add_event(ev_sigint, NULL) != 0 || main_event_mgr->add_event(ev_sigterm, NULL) != 0 ||
            main_event_mgr->add_event(ev_sigusr1, NULL) != 0 || main_event_mgr->add_event(ev_timeout, &event_time) != 0||
            main_event_mgr->add_event(ev_db_update, &db_update_event_time) != 0 ||
            main_event_mgr->add_event(ev_sigusr2, NULL) != 0) {
            syslog(LOG_ERR, "Failed to add event for main thread");
            exit(1);
        }

        if(rx_event_mgr->add_event(ev_rx_cache_counter_update, NULL) != 0 || tx_event_mgr->add_event(ev_tx_cache_counter_update, NULL) != 0) {
            syslog(LOG_ERR, "Failed to add RX/TX cache counter callback event for rx/tx thread");
            exit(1);
        }

        std::thread sub_thread_rx(rx_sub_thread_dispatch);
        std::thread sub_thread_tx(tx_sub_thread_dispatch);

        if (event_base_dispatch(main_event_mgr->get_base()) != 0) {
            syslog(LOG_ERR, "Could not start libevent dispatching loop!\n");
            break;
        }
        sub_thread_rx.join();
        sub_thread_tx.join();

        rv = 0;
    } while (0);

    return rv;
}

/**
 * @code dhcp_mon_stop();
 *
 * @brief stop monitoring DHCP Relay
 */
void dhcp_mon_stop()
{
    event_base_loopbreak(rx_event_mgr->get_base());
    event_base_loopbreak(tx_event_mgr->get_base());
    event_base_loopexit(main_event_mgr->get_base(), NULL);
}
