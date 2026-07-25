/**
 * @file dhcp_check.cpp
 * DHCP health check implementation
 */

#include <syslog.h>
#include <algorithm>
#include <mutex>
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

static std::unordered_set<int> reported_disparity_v4;
static std::mutex health_state_mutex;

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

static void check_relay_disparity()
{
    auto windows_by_type = dhcp_device_get_untransmitted_windows(agg_dev_all);
    uint32_t report_windows = 0;

    for (const auto &[msg_type, windows] : windows_by_type) {
        if (windows == 0) {
            reported_disparity_v4.erase(msg_type);
            continue;
        }
        if (windows > static_cast<uint32_t>(dhcp_unhealthy_max_count) &&
            reported_disparity_v4.insert(msg_type).second) {
            report_windows = std::max(report_windows, windows);
        }
    }

    if (report_windows > 0) {
        int duration = static_cast<int>(report_windows) * window_interval_sec;
        alert_dhcp_relay_disparity(duration);
        log_agg_error(duration);
    }
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
        .check_health = check_mgmt_health,
        .log = log_mgmt_error,
        .count = 0,
        .reported = false,
    },
    [1] = {
        .check_health = check_mgmt_health_v6,
        .log = log_mgmt_error,
        .count = 0,
        .reported = false,
    },
    [2] = {
        .check_health = check_per_interface_rx_health,
        .log = log_agg_per_interface_rx_error,
        .count = 0,
        .reported = false,
    },
    [3] = {
        .check_health = check_per_interface_tx_health,
        .log = log_agg_per_interface_tx_error,
        .count = 0,
        .reported = false,
    },
    [4] = {
        .check_health = check_per_interface_rx_health_v6,
        .log = log_agg_per_interface_rx_error,
        .count = 0,
        .reported = false,
    },
    [5] = {
        .check_health = check_per_interface_tx_health_v6,
        .log = log_agg_per_interface_tx_error,
        .count = 0,
        .reported = false,
    },
};

static size_t state_data_sz = sizeof(state_data) / sizeof(*state_data);

void check_dhcp_relay_health()
{
    std::lock_guard<std::mutex> lock(health_state_mutex);
    syslog_debug(LOG_INFO, "Checking DHCP relay health");

    check_relay_disparity();

    for (uint8_t i = 0; i < state_data_sz; i++) {
        dhcp_mon_status_t dhcp_mon_status = state_data[i].check_health();
        switch (dhcp_mon_status) {
            case DHCP_MON_STATUS_UNHEALTHY:
                if (++state_data[i].count > dhcp_unhealthy_max_count && !state_data[i].reported) {
                    int duration = state_data[i].count * window_interval_sec;
                
                    if (state_data[i].alert) {
                        state_data[i].alert(duration);
                    }
                    if (state_data[i].log) {
                        state_data[i].log(duration);
                    }
                    state_data[i].reported = true;
                }
                break;
            case DHCP_MON_STATUS_HEALTHY:
                state_data[i].count = 0;
                state_data[i].reported = false;
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

void reset_dhcp_relay_health_state(const std::string &ifname)
{
    std::lock_guard<std::mutex> lock(health_state_mutex);
    reported_disparity_v4.clear();
    for (auto &state : state_data) {
        state.count = 0;
        state.reported = false;
    }
    dhcp_device_reset_health_state(ifname);
}