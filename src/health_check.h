/**
 * @file health_check.h
 * DHCP health check module
 */

#ifndef HEALTH_CHECK_H
#define HEALTH_CHECK_H

#include "dhcp_device.h"

#include <swss/events.h>

/** DHCP device/interface state */
typedef struct
{
    dhcp_mon_status_t (*check_health)();           /** check function */
    void (*alert)(int duration);                   /** alert function when check failed */
    void (*log)(int duration);                     /** log function when check passed */
    int count;                                     /** count in the number of unhealthy checks */
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

#endif // HEALTH_CHECK_H