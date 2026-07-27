/**
 * @file health_check.h
 * DHCP health check module
 */

#ifndef HEALTH_CHECK_H
#define HEALTH_CHECK_H

#include "dhcp_device.h"

#include <cstdint>
#include <swss/events.h>
#include <string>
#include <unordered_map>

/** DHCP device/interface state */
typedef struct
{
    dhcp_mon_status_t (*check_health)();           /** check function */
    void (*alert)(int duration);                   /** alert function when unhealthy threshold is crossed */
    void (*log)(int duration);                     /** log function when unhealthy threshold is crossed */
    int64_t count;                                 /** consecutive unhealthy/indeterminate health windows */
    bool reported;                                 /** whether the current unhealthy episode was reported */
} dhcp_mon_state_t;

extern event_handle_t g_events_handle;

extern int window_interval_sec;

extern int dhcp_unhealthy_max_count;

/**
 * @code check_dhcp_relay_health(state_data);
 *
 * @brief check DHCP relay overall health
 *
 * @param none
 *
 * @return none
 */
void check_dhcp_relay_health();

/** Reset relay state after counter replacement */
void reset_dhcp_relay_health_state(const std::string &ifname);
void reset_dhcp_relay_health_state(
    const std::string &ifname,
    const std::unordered_map<uint8_t, uint64_t> &rx_counters,
    const std::unordered_map<uint8_t, uint64_t> &tx_counters);

#endif // HEALTH_CHECK_H