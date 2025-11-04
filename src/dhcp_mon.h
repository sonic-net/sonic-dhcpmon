/**
 * @file dhcp_mon.h
 *
 * dhcp monitor module, which implements the main structure and threads of the program
 * besides the dhcp_mon_* functions, it also hosts database accesses and event loop management.
 * Functions are noop on failure.
 */

#ifndef DHCP_MON_H_
#define DHCP_MON_H_

/** dhcpmon debug mode control flag, mostly used for logging for more frequent operations */
extern bool debug_on;

 /**
  * @code dhcp_mon_init(snaplen, window_sec, max_count, dbu_update_interval);
  * 
  * @brief initializes event base and periodic timer event that continuously collects dhcp relay health status every
  *        window_sec seconds. It also writes to syslog when dhcp relay has been unhealthy for consecutive max_count
  *        checks.
  * @param snaplen             snaplen for packet capture
  * @param window_sec          time interval between health checks
  * @param max_count           max count of consecutive unhealthy statuses before reporting to syslog
  * @param db_update_interval  time interval of updating COUNTERS_DB
  * @return 0 upon success, negative upon failure
  */
int dhcp_mon_init(size_t snaplen, int window_sec, int max_count, int db_update_interval);

/**
 * @code dhcp_mon_free();
 *
 * @brief frees resources used by dhcp monitor
 *
 * @return none
 */
void dhcp_mon_free();

/**
 * @code dhcp_mon_start(debug);
 *
 * @brief start monitoring DHCP Relay
 *
 * @param none
 *
 * @return 0 upon success, negative upon failure
 */
int dhcp_mon_start();

/**
 * @code dhcp_mon_stop();
 *
 * @brief stop monitoring DHCP Relay
 *
 * @return none
 */
void dhcp_mon_stop();

#endif /* DHCP_MON_H_ */
