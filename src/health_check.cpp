/**
 * @file dhcp_check.cpp
 * DHCP health check implementation
 */

#include <syslog.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "health_check.h"

#include "util.h"

event_handle_t g_events_handle;

/** window_interval_sec monitoring window for dhcp relay health checks */
int window_interval_sec = 18;
/** dhcp_unhealthy_max_count max count of consecutive unhealthy statuses before reporting to syslog */
int dhcp_unhealthy_max_count = 10;

extern std::string mgmt_ifname;

extern std::string agg_dev_all;

extern bool dhcpv4_enabled;
extern bool dhcpv6_enabled;

extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_vlan_map;
extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_portchan_map;

static const char relay_disparity_error[] =
    "dhcpmon detected DHCPv4/v6 packets received but none transmitted for intf: %s. Duration: %d (sec)";
static const char mgmt_error[] =
    "dhcpmon detected DHCP packets traveling through mgmt interface (please check BGP routes.)"
    " Intf: %s. Duration: %d (sec)";
static const char agg_rx_disparity_error[] =
    "dhcpmon detected an IPv4 RX disparity between interface %s and the aggregate of its member interface counters."
    " Duration: %d (sec)";
static const char agg_tx_disparity_error[] =
    "dhcpmon detected an IPv4 TX disparity between interface %s and the aggregate of its member interface counters."
    " Duration: %d (sec)";
static const char agg_rx_v6_disparity_error[] =
    "dhcpmon detected an IPv6 RX disparity between interface %s and the aggregate of its member interface counters."
    " Duration: %d (sec)";
static const char agg_tx_v6_disparity_error[] =
    "dhcpmon detected an IPv6 TX disparity between interface %s and the aggregate of its member interface counters."
    " Duration: %d (sec)";

/**
 * @code alert_dhcp_relay_disparity(duration);
 *
 * @brief Publish the existing DHCP relay disparity event
 *
 * @param duration Unhealthy duration in seconds
 *
 * @return None
 */
static void alert_dhcp_relay_disparity(int duration)
{
    event_params_t params = {{ "vlan", agg_dev_all}, { "duration", std::to_string(duration)}};
    event_publish(g_events_handle, "dhcp-relay-disparity", &params);
}

static std::vector<dhcp_mon_state_t> state_data;

void initialize_dhcp_relay_health()
{
    state_data.clear();

    state_data.push_back({agg_dev_all, DHCP_DEVICE_CHECK_POSITIVE, alert_dhcp_relay_disparity,
                          relay_disparity_error, 0, false});
    if (mgmt_ifname.size() > 0) {
        state_data.push_back({mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE, NULL, mgmt_error, 0, false});
    }
    state_data.push_back({agg_dev_all, DHCP_DEVICE_CHECK_POSITIVE_V6, alert_dhcp_relay_disparity,
                          relay_disparity_error, 0, true});
    if (mgmt_ifname.size() > 0) {
        state_data.push_back({mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE_V6, NULL, mgmt_error, 0, true});
    }

    for (const auto &[vlan, _] : rev_vlan_map) {
        state_data.push_back({vlan, DHCP_DEVICE_CHECK_AGG_RX, NULL, agg_rx_disparity_error, 0, false});
        state_data.push_back({vlan, DHCP_DEVICE_CHECK_AGG_TX, NULL, agg_tx_disparity_error, 0, false});
        state_data.push_back({vlan, DHCP_DEVICE_CHECK_AGG_RX_V6, NULL, agg_rx_v6_disparity_error, 0, true});
        state_data.push_back({vlan, DHCP_DEVICE_CHECK_AGG_TX_V6, NULL, agg_tx_v6_disparity_error, 0, true});
    }

    for (const auto &[portchan, _] : rev_portchan_map) {
        state_data.push_back({portchan, DHCP_DEVICE_CHECK_AGG_RX, NULL, agg_rx_disparity_error, 0, false});
        state_data.push_back({portchan, DHCP_DEVICE_CHECK_AGG_TX, NULL, agg_tx_disparity_error, 0, false});
        state_data.push_back({portchan, DHCP_DEVICE_CHECK_AGG_RX_V6, NULL, agg_rx_v6_disparity_error, 0, true});
        state_data.push_back({portchan, DHCP_DEVICE_CHECK_AGG_TX_V6, NULL, agg_tx_v6_disparity_error, 0, true});
    }
}

void check_dhcp_relay_health()
{
    syslog_debug(LOG_INFO, "Checking DHCP relay health");

    for (auto &state : state_data) {
        if ((state.is_v6 && !dhcpv6_enabled) ||
            (!state.is_v6 && !dhcpv4_enabled)) {
            continue;
        }
        dhcp_mon_status_t dhcp_mon_status = dhcp_device_get_status(state.ifname, state.check_type);
        switch (dhcp_mon_status) {
            case DHCP_MON_STATUS_UNHEALTHY:
                if (++state.count > dhcp_unhealthy_max_count) {
                    int duration = state.count * window_interval_sec;
                
                    if (state.alert) {
                        state.alert(duration);
                    }
                    syslog(LOG_ALERT, state.error_format, state.ifname.c_str(), duration);
                }
                break;
            case DHCP_MON_STATUS_HEALTHY:
                state.count = 0;
                break;
            case DHCP_MON_STATUS_INDETERMINATE:
                if (state.count) {
                    state.count++;
                }
                break;
            default:
                syslog(LOG_ALERT, "DHCP Relay returned unknown status %d", dhcp_mon_status);
                break;
        }
    }

    syslog_debug(LOG_INFO, "Completed DHCP relay health check");
}