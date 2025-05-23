/**
 * @file dhcp_mon.h
 *
 *  @brief dhcp relay monitor module
 *
 */

#ifndef DHCP_MON_H_
#define DHCP_MON_H_

#include <mutex>
#include "util.h"

/**
 * @code dhcp_mon_init(window_ssec, max_count, db_update_interval);
 *
 * @brief initializes event base and periodic timer event that continuously collects dhcp relay health status every
 *        window_sec seconds. It also writes to syslog when dhcp relay has been unhealthy for consecutive max_count
 *        checks.
 *
 * @param window_sec time interval between health checks
 * @param max_count max count of consecutive unhealthy statuses before reporting to syslog
 * @param db_update_interval time interval of updating COUNTERS_DB
 *
 * @return 0 upon success, otherwise upon failure
 */
int dhcp_mon_init(int window_sec, int max_count, int db_update_interval);

/**
 * @code dhcp_mon_shutdown();
 *
 * @brief shuts down libevent loop
 *
 * @return none
 */
void dhcp_mon_shutdown();

/**
 * @code dhcp_mon_start(snaplen, debug);
 *
 * @brief start monitoring DHCP Relay
 *
 * @param snaplen       packet capture length
 * @param debug         turn on debug or not
 *
 * @return 0 upon success, otherwise upon failure
 */
int dhcp_mon_start(size_t snaplen, bool debug);

/**
 * @code free_event_mgr(struct event_mgr *mgr);
 *
 * @brief Free event manager
 * 
 * @param mgr pointer to event manager
 */
void free_event_mgr(struct event_mgr *mgr);

/**
 * @code dhcp_mon_stop();
 *
 * @brief stop monitoring DHCP Relay
 *
 * @return none
 */
void dhcp_mon_stop();

#endif /* DHCP_MON_H_ */
