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
#include <syslog.h>
#include <assert.h>

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
/** window_interval_sec monitoring window for dhcp relay health checks */
static int db_update_interval_sec;

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
    std::string table_name;
    for (const auto& outer_pair : *counter) {
        const std::string interface_name = outer_pair.first;
        const auto* inner_map = &outer_pair.second;
        std::string value = generate_json_string(inner_map);
        /**
         * Only add downstream prefix for non-downstream interface
         */
        if (downstream_if_name.compare(interface_name) != 0) {
            table_name = DB_COUNTER_TABLE_PREFIX + downstream_if_name + COUNTERS_DB_SEPARATOR + interface_name;
        } else {
            table_name = DB_COUNTER_TABLE_PREFIX + interface_name;
        }
        mCountersDbPtr->hset(table_name, (dir == DHCP_RX) ? "RX" : "TX", value);
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
    update_counter(DHCP_RX);
    update_counter(DHCP_TX);
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

        struct event *ev_timeout = event_new(main_event_mgr->get_base(), -1, EV_PERSIST, timeout_callback, main_event_mgr->get_base());
        if (ev_timeout == NULL) {
            syslog(LOG_ERR, "Could not create libevent timer!\n");
            break;
        }

        struct event *ev_db_update = event_new(main_event_mgr->get_base(), -1, EV_PERSIST, db_update_callback, main_event_mgr->get_base());
        if (ev_db_update == NULL) {
            syslog(LOG_ERR, "Could not create db update timer!\n");
            break;
        }

        struct timeval event_time = {.tv_sec = window_interval_sec, .tv_usec = 0};
        struct timeval db_update_event_time = {.tv_sec = db_update_interval_sec, .tv_usec = 0};

        if (main_event_mgr->add_event(ev_sigint, NULL) != 0 || main_event_mgr->add_event(ev_sigterm, NULL) != 0 ||
            main_event_mgr->add_event(ev_sigusr1, NULL) != 0 || main_event_mgr->add_event(ev_timeout, &event_time) != 0||
            main_event_mgr->add_event(ev_db_update, &db_update_event_time) != 0) {
            syslog(LOG_ERR, "Failed to add event for main thread");
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
