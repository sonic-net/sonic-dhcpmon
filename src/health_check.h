/**
 * @file health_check.h
 * DHCP health check module
 */

#ifndef HEALTH_CHECK_H
#define HEALTH_CHECK_H

#include "dhcp_device.h"

#include <swss/events.h>
#include <string>

/** DHCP device/interface state */
typedef struct
{
    std::string ifname;                     /** interface to check */
    dhcp_device_check_t check_type;         /** check to apply */
    void (*alert)(int duration);            /** alert function */
    const char *error_format;               /** threshold error format */
    int count;                              /** consecutive unhealthy checks */
    bool is_v6;                             /** whether this state monitors DHCPv6 */
} dhcp_mon_state_t;

extern event_handle_t g_events_handle;

extern int window_interval_sec;

extern int dhcp_unhealthy_max_count;

/**
 * @code initialize_dhcp_relay_health();
 *
 * @brief Populate health states from discovered VLAN and PortChannel members
 *
 * @param none
 *
 * @return none
 */
void initialize_dhcp_relay_health();

/**
 * @code check_dhcp_relay_health();
 *
 * @brief check DHCP relay overall health
 *
 * @param none
 *
 * @return none
 */
void check_dhcp_relay_health();

#endif // HEALTH_CHECK_H