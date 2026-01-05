/**
 * @file dhcp_check.cpp
 * DHCP health check implementation
 */

#include <syslog.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "health_check.h"

#include "util.h"

event_handle_t g_events_handle;

/** window_interval_sec monitoring window for dhcp relay health checks */
int window_interval_sec = 18;
/** dhcp_unhealthy_max_count max count of consecutive unhealthy statuses before reporting to syslog */
int dhcp_unhealthy_max_count = 10;

extern std::string mgmt_ifname;

extern std::string agg_dev_all;
extern std::string agg_dev_prefix;

extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_vlan_map;
extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_portchan_map;

static dhcp_mon_status_t check_agg_health()
{
    return dhcp_device_get_status(agg_dev_all, DHCP_DEVICE_CHECK_POSITIVE);
}

static dhcp_mon_status_t check_mgmt_health()
{
    if (mgmt_ifname.size() > 0) {
        return dhcp_device_get_status(mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE);
    }
    return DHCP_MON_STATUS_HEALTHY;
}

static void alert_dhcp_relay_disparity(int duration)
{
    event_params_t params = {{ "vlan", agg_dev_all}, { "duration", std::to_string(duration)}};
    event_publish(g_events_handle, "dhcp-relay-disparity", &params);
}

static void log_agg_error(int duration)
{
    syslog(LOG_ALERT, "dhcpmon detected DHCPv4/v6 packets received but none transmitted. Duration: %d (sec) for intf: %s",
           duration, agg_dev_all.c_str());
}

static void log_mgmt_error(int duration)
{
    syslog(LOG_ALERT, "dhcpmon detected DHCP packets traveling through mgmt interface (please check BGP routes.)"
                      " Duration: %d (sec) for intf: %s",
           duration, mgmt_ifname.c_str());
}

static dhcp_mon_status_t check_agg_health_v6()
{
    return dhcp_device_get_status(agg_dev_all, DHCP_DEVICE_CHECK_POSITIVE_V6);
}

static dhcp_mon_status_t check_mgmt_health_v6()
{
    if (mgmt_ifname.size() > 0) {
        return dhcp_device_get_status(mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE_V6);
    }
    return DHCP_MON_STATUS_HEALTHY;
}

static dhcp_mon_status_t check_per_interface_rx_health()
{
    for (const auto &[vlan, _] : rev_vlan_map) {
        if (dhcp_device_get_status(vlan, DHCP_DEVICE_CHECK_AGG_EQUAL_RX) == DHCP_MON_STATUS_UNHEALTHY) {
            return DHCP_MON_STATUS_UNHEALTHY;
        }
    }
    for (const auto &[portchan, _] : rev_portchan_map) {
        if (dhcp_device_get_status(portchan, DHCP_DEVICE_CHECK_AGG_EQUAL_RX) == DHCP_MON_STATUS_UNHEALTHY) {
            return DHCP_MON_STATUS_UNHEALTHY;
        }
    }
    return DHCP_MON_STATUS_HEALTHY;
}

static void log_agg_per_interface_rx_error(int duration)
{
    syslog(LOG_ALERT, "sum of rx per interface counter does not equal corresponding vlan/portchan counter."
           " Duration: %d (sec)", duration);
}

static dhcp_mon_status_t check_per_interface_tx_health()
{
    for (const auto &[vlan, _] : rev_vlan_map) {
        if (dhcp_device_get_status(vlan, DHCP_DEVICE_CHECK_AGG_MULTIPLE_TX) == DHCP_MON_STATUS_UNHEALTHY) {
            return DHCP_MON_STATUS_UNHEALTHY;
        }
    }
    for (const auto &[portchan, _] : rev_portchan_map) {
        if (dhcp_device_get_status(portchan, DHCP_DEVICE_CHECK_AGG_EQUAL_TX) == DHCP_MON_STATUS_UNHEALTHY) {
            return DHCP_MON_STATUS_UNHEALTHY;
        }
    }
    return DHCP_MON_STATUS_HEALTHY;
}

static void log_agg_per_interface_tx_error(int duration)
{
    syslog(LOG_ALERT, "each tx per interface counter does not equal corresponding vlan counter,"
           " or sum of tx per interface counter does not equal corresponding portchan counter."
           " Duration: %d (sec)", duration);
}

static dhcp_mon_status_t check_per_interface_rx_health_v6()
{
    for (const auto &[vlan, _] : rev_vlan_map) {
        if (dhcp_device_get_status(vlan, DHCP_DEVICE_CHECK_AGG_EQUAL_RX_V6) == DHCP_MON_STATUS_UNHEALTHY) {
            return DHCP_MON_STATUS_UNHEALTHY;
        }
    }
    for (const auto &[portchan, _] : rev_portchan_map) {
        if (dhcp_device_get_status(portchan, DHCP_DEVICE_CHECK_AGG_EQUAL_RX_V6) == DHCP_MON_STATUS_UNHEALTHY) {
            return DHCP_MON_STATUS_UNHEALTHY;
        }
    }
    return DHCP_MON_STATUS_HEALTHY;
}

static dhcp_mon_status_t check_per_interface_tx_health_v6()
{
    for (const auto &[vlan, _] : rev_vlan_map) {
        if (dhcp_device_get_status(vlan, DHCP_DEVICE_CHECK_AGG_MULTIPLE_TX_V6) == DHCP_MON_STATUS_UNHEALTHY) {
            return DHCP_MON_STATUS_UNHEALTHY;
        }
    }
    for (const auto &[portchan, _] : rev_portchan_map) {
        if (dhcp_device_get_status(portchan, DHCP_DEVICE_CHECK_AGG_EQUAL_TX_V6) == DHCP_MON_STATUS_UNHEALTHY) {
            return DHCP_MON_STATUS_UNHEALTHY;
        }
    }
    return DHCP_MON_STATUS_HEALTHY;
}

/** DHCP monitor state data for aggregate device for mgmt device */
static dhcp_mon_state_t state_data[] = {
    [0] = {
        .check_health = check_agg_health,
        .alert = alert_dhcp_relay_disparity,
        .log = log_agg_error,
        .count = 0,
    },
    [1] = {
        .check_health = check_mgmt_health,
        .log = log_mgmt_error,
        .count = 0,
    },
    [2] = {
        .check_health = check_agg_health_v6,
        .alert = alert_dhcp_relay_disparity,
        .log = log_agg_error,
        .count = 0,
    },
    [3] = {
        .check_health = check_mgmt_health_v6,
        .log = log_mgmt_error,
        .count = 0,
    },
    [4] = {
        .check_health = check_per_interface_rx_health,
        .log = log_agg_per_interface_rx_error,
        .count = 0,
    },
    [5] = {
        .check_health = check_per_interface_tx_health,
        .log = log_agg_per_interface_tx_error,
        .count = 0,
    },
    [6] = {
        .check_health = check_per_interface_rx_health_v6,
        .log = log_agg_per_interface_rx_error,
        .count = 0,
    },
    [7] = {
        .check_health = check_per_interface_tx_health_v6,
        .log = log_agg_per_interface_tx_error,
        .count = 0,
    },
};

static size_t state_data_sz = sizeof(state_data) / sizeof(*state_data);

void check_dhcp_relay_health()
{
    syslog_debug(LOG_INFO, "Checking DHCP relay health");

    for (uint8_t i = 0; i < state_data_sz; i++) {
        dhcp_mon_status_t dhcp_mon_status = state_data[i].check_health();
        switch (dhcp_mon_status) {
            case DHCP_MON_STATUS_UNHEALTHY:
                if (++state_data[i].count > dhcp_unhealthy_max_count) {
                    int duration = state_data[i].count * window_interval_sec;
                
                    if (state_data[i].alert) {
                        state_data[i].alert(duration);
                    }
                    if (state_data[i].log) {
                        state_data[i].log(duration);
                    }
                }
                break;
            case DHCP_MON_STATUS_HEALTHY:
                state_data[i].count = 0;
                break;
            case DHCP_MON_STATUS_INDETERMINATE:
                if (state_data[i].count) {
                    state_data[i].count++;
                }
                break;
            default:
                syslog(LOG_ALERT, "DHCP Relay returned unknown status %d", dhcp_mon_status);
                break;
        }
    }

    syslog_debug(LOG_INFO, "Completed DHCP relay health check");
}