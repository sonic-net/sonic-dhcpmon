/**
 * @file health_accounting_test.cpp
 * Counter-driven regression cases for the real public health evaluator and snapshot logic.
 * Run with make test-health in the existing SONiC CI build environment.
 */

#include <exception>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "dhcp_device.h"
#include "sock_mgr.h"

namespace swss {
class DBConnector;
class Table;
}

// Exclude dhcp_mon.cpp and its eager Redis connections from this executable.
// The real health and socket-counter functions do not use these empty handles.
std::shared_ptr<swss::DBConnector> mConfigDbPtr;
std::shared_ptr<swss::DBConnector> mCountersDbPtr;
std::shared_ptr<swss::DBConnector> mStateDbPtr;
std::shared_ptr<swss::Table> mStateDbMuxTablePtr;

extern std::unordered_map<int, sock_info_t> sock_map;
extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_vlan_map;
extern std::string agg_dev_prefix;

static const int rx_fd = 100;
static const int tx_fd = 101;
static const int rx_fd_v6 = 102;
static const int tx_fd_v6 = 103;
static const char flow_ifname[] = "Agg-All";
static const char mgmt_ifname[] = "eth0";
static const char parent_ifname[] = "Vlan1000";
static const char member_agg_ifname[] = "Agg-Vlan1000";

typedef struct {
    int sock;
    std::string ifname;
    int msg_type;
    uint64_t delta;
} counter_change_t;

typedef struct {
    std::string name;
    std::string ifname;
    dhcp_device_check_t check_type;
    std::vector<counter_change_t> changes;
    dhcp_mon_status_t expected;
} health_case_t;

/**
 * @brief Initialize real socket-manager counters and a nonzero snapshot without opening sockets.
 */
static void initialize_counters()
{
    sock_map.clear();
    rx_sock = rx_fd;
    tx_sock = tx_fd;
    rx_sock_v6 = rx_fd_v6;
    tx_sock_v6 = tx_fd_v6;
    agg_dev_prefix = "Agg-";
    rev_vlan_map.clear();
    rev_vlan_map[parent_ifname] = {"Ethernet0", "Ethernet4"};

    for (int sock : {rx_fd, tx_fd, rx_fd_v6, tx_fd_v6}) {
        sock_info_t &info = sock_map[sock];
        info.sock = sock;
        info.name = "health-test";
        info.is_rx = sock == rx_fd || sock == rx_fd_v6;
        info.is_v6 = sock == rx_fd_v6 || sock == tx_fd_v6;
    }
    for (const char *ifname : {flow_ifname, mgmt_ifname, parent_ifname, member_agg_ifname,
                              "PortChannel1", "Agg-PortChannel1"}) {
        sock_mgr_init_cache_counters(ifname, DHCP_MESSAGE_TYPE_COUNT, DHCPV6_MESSAGE_TYPE_COUNT);
    }
    for (auto &[sock, info] : sock_map) {
        for (auto &[ifname, counters] : info.all_counters) {
            for (auto &[msg_type, count] : counters) {
                count = 100;
            }
        }
    }
    sock_mgr_update_snapshot();
}

/**
 * @brief Construct independent expected outcomes for relay flow and retained non-flow policies.
 */
static std::vector<health_case_t> make_cases()
{
    std::vector<health_case_t> cases;
    const dhcpv6_message_type_t forward_msgs_v6[] = {
        DHCPV6_MESSAGE_TYPE_SOLICIT, DHCPV6_MESSAGE_TYPE_REQUEST, DHCPV6_MESSAGE_TYPE_CONFIRM,
        DHCPV6_MESSAGE_TYPE_RENEW, DHCPV6_MESSAGE_TYPE_REBIND, DHCPV6_MESSAGE_TYPE_RELEASE,
        DHCPV6_MESSAGE_TYPE_DECLINE, DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST, DHCPV6_MESSAGE_TYPE_RELAY_FORW
    };
    const dhcpv6_message_type_t reply_msgs_v6[] = {
        DHCPV6_MESSAGE_TYPE_ADVERTISE, DHCPV6_MESSAGE_TYPE_REPLY,
        DHCPV6_MESSAGE_TYPE_RECONFIGURE, DHCPV6_MESSAGE_TYPE_RELAY_REPL
    };
    const dhcpv6_message_type_t error_msgs_v6[] = {
        DHCPV6_MESSAGE_TYPE_UNKNOWN, DHCPV6_MESSAGE_TYPE_MALFORMED, DHCPV6_MESSAGE_TYPE_IGNORED
    };
    const dhcpv6_message_type_t path_msgs_v6[] = {
        DHCPV6_MESSAGE_TYPE_SOLICIT, DHCPV6_MESSAGE_TYPE_ADVERTISE, DHCPV6_MESSAGE_TYPE_REQUEST,
        DHCPV6_MESSAGE_TYPE_REPLY, DHCPV6_MESSAGE_TYPE_RELAY_FORW, DHCPV6_MESSAGE_TYPE_RELAY_REPL
    };
    const dhcpv6_message_type_t excluded_path_msgs_v6[] = {
        DHCPV6_MESSAGE_TYPE_CONFIRM, DHCPV6_MESSAGE_TYPE_RENEW, DHCPV6_MESSAGE_TYPE_REBIND,
        DHCPV6_MESSAGE_TYPE_RELEASE, DHCPV6_MESSAGE_TYPE_DECLINE,
        DHCPV6_MESSAGE_TYPE_INFORMATION_REQUEST, DHCPV6_MESSAGE_TYPE_RECONFIGURE
    };
    const dhcp_message_type_t flow_msgs[] = {
        DHCP_MESSAGE_TYPE_DISCOVER, DHCP_MESSAGE_TYPE_OFFER, DHCP_MESSAGE_TYPE_REQUEST, DHCP_MESSAGE_TYPE_ACK
    };

    cases.push_back({"v6 idle", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6, {}, DHCP_MON_STATUS_INDETERMINATE});
    for (dhcpv6_message_type_t msg_type : forward_msgs_v6) {
        const std::string name = db_counter_name_v6[msg_type];
        cases.push_back({name + " -> Relay-Forward", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                         {{rx_fd_v6, flow_ifname, msg_type, 1},
                          {tx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_FORW, 1}}, DHCP_MON_STATUS_HEALTHY});
        cases.push_back({name + " without TX opens activity gate", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                         {{rx_fd_v6, flow_ifname, msg_type, 1}}, DHCP_MON_STATUS_UNHEALTHY});
        cases.push_back({name + " uses presence, not count equality", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                         {{rx_fd_v6, flow_ifname, msg_type, 3},
                          {tx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_FORW, 1}}, DHCP_MON_STATUS_HEALTHY});
    }
    for (dhcpv6_message_type_t msg_type : reply_msgs_v6) {
        const std::string name = db_counter_name_v6[msg_type];
        cases.push_back({"Relay-Reply -> " + name, flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                         {{rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_REPL, 1},
                          {tx_fd_v6, flow_ifname, msg_type, 1}}, DHCP_MON_STATUS_HEALTHY});
        cases.push_back({"Relay-Reply -> " + name + " uses presence", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                         {{rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_REPL, 3},
                          {tx_fd_v6, flow_ifname, msg_type, 1}}, DHCP_MON_STATUS_HEALTHY});
        cases.push_back({name + " TX only", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                         {{tx_fd_v6, flow_ifname, msg_type, 1}}, DHCP_MON_STATUS_INDETERMINATE});
    }
    cases.push_back({"Relay-Forward TX only", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                     {{tx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_FORW, 1}}, DHCP_MON_STATUS_INDETERMINATE});
    cases.push_back({"Relay-Reply without TX", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                     {{rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_REPL, 1}}, DHCP_MON_STATUS_UNHEALTHY});
    cases.push_back({"both relay directions", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                     {{rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RENEW, 1},
                      {tx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_FORW, 1},
                      {rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_REPL, 1},
                      {tx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RECONFIGURE, 1}}, DHCP_MON_STATUS_HEALTHY});
    cases.push_back({"reply output cannot satisfy forward RX", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                     {{rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RENEW, 1},
                      {rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_REPL, 1},
                      {tx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RECONFIGURE, 1}}, DHCP_MON_STATUS_UNHEALTHY});
    cases.push_back({"forward output cannot satisfy reply RX", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                     {{rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RENEW, 1},
                      {tx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_FORW, 1},
                      {rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_RELAY_REPL, 1}}, DHCP_MON_STATUS_UNHEALTHY});
    for (dhcpv6_message_type_t msg_type : error_msgs_v6) {
        const std::string name = db_counter_name_v6[msg_type];
        cases.push_back({name + " only is idle", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                         {{rx_fd_v6, flow_ifname, msg_type, 1},
                          {tx_fd_v6, flow_ifname, msg_type, 1}}, DHCP_MON_STATUS_INDETERMINATE});
        for (dhcpv6_message_type_t rx_type : {DHCPV6_MESSAGE_TYPE_CONFIRM, DHCPV6_MESSAGE_TYPE_RELAY_REPL}) {
            cases.push_back({name + " TX cannot satisfy " + db_counter_name_v6[rx_type],
                             flow_ifname, DHCP_DEVICE_CHECK_POSITIVE_V6,
                             {{rx_fd_v6, flow_ifname, rx_type, 1},
                              {tx_fd_v6, flow_ifname, msg_type, 1}}, DHCP_MON_STATUS_UNHEALTHY});
        }
    }

    for (dhcpv6_message_type_t msg_type : excluded_path_msgs_v6) {
        const std::string name = db_counter_name_v6[msg_type];
        cases.push_back({name + " retains management activity gate", mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE_V6,
                         {{tx_fd_v6, mgmt_ifname, msg_type, 1}}, DHCP_MON_STATUS_INDETERMINATE});
        cases.push_back({name + " remains outside management TX policy", mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE_V6,
                         {{rx_fd_v6, mgmt_ifname, DHCPV6_MESSAGE_TYPE_RELAY_REPL, 1},
                          {tx_fd_v6, mgmt_ifname, msg_type, 1}}, DHCP_MON_STATUS_HEALTHY});
        for (int sock : {rx_fd_v6, tx_fd_v6}) {
            const dhcp_device_check_t check_type = sock == rx_fd_v6 ?
                                                  DHCP_DEVICE_CHECK_AGG_RX_V6 : DHCP_DEVICE_CHECK_AGG_TX_V6;
            cases.push_back({name + " retains aggregate activity gate", parent_ifname, check_type,
                             {{sock, parent_ifname, msg_type, 1}}, DHCP_MON_STATUS_INDETERMINATE});
            cases.push_back({name + " remains outside aggregate comparison", parent_ifname, check_type,
                             {{sock, parent_ifname, DHCPV6_MESSAGE_TYPE_RELAY_FORW, 1},
                              {sock, member_agg_ifname, DHCPV6_MESSAGE_TYPE_RELAY_FORW, 1},
                              {sock, parent_ifname, msg_type, 1}}, DHCP_MON_STATUS_HEALTHY});
        }
    }
    for (dhcpv6_message_type_t msg_type : path_msgs_v6) {
        const std::string name = db_counter_name_v6[msg_type];
        cases.push_back({name + " management TX", mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE_V6,
                         {{tx_fd_v6, mgmt_ifname, msg_type, 1}}, DHCP_MON_STATUS_UNHEALTHY});
        for (int sock : {rx_fd_v6, tx_fd_v6}) {
            const dhcp_device_check_t check_type = sock == rx_fd_v6 ?
                                                  DHCP_DEVICE_CHECK_AGG_RX_V6 : DHCP_DEVICE_CHECK_AGG_TX_V6;
            cases.push_back({name + " matching parent/member", parent_ifname, check_type,
                             {{sock, parent_ifname, msg_type, 1},
                              {sock, member_agg_ifname, msg_type, 1}}, DHCP_MON_STATUS_HEALTHY});
            cases.push_back({name + " parent-only activity", parent_ifname, check_type,
                             {{sock, parent_ifname, msg_type, 1}}, DHCP_MON_STATUS_UNHEALTHY});
            cases.push_back({name + " member-only activity", parent_ifname, check_type,
                             {{sock, member_agg_ifname, msg_type, 1}}, DHCP_MON_STATUS_UNHEALTHY});
            cases.push_back({name + " v6 requires exact parent/member counts", parent_ifname, check_type,
                             {{sock, parent_ifname, msg_type, 1},
                              {sock, member_agg_ifname, msg_type, 2}}, DHCP_MON_STATUS_UNHEALTHY});
        }
    }

    cases.push_back({"v4 idle", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE, {}, DHCP_MON_STATUS_INDETERMINATE});
    for (dhcp_message_type_t msg_type : flow_msgs) {
        const std::string name = db_counter_name[msg_type];
        cases.push_back({name + " v4 uses presence", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE,
                         {{rx_fd, flow_ifname, msg_type, 3},
                          {tx_fd, flow_ifname, msg_type, 1}}, DHCP_MON_STATUS_HEALTHY});
        cases.push_back({name + " v4 requires same-type TX", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE,
                         {{rx_fd, flow_ifname, msg_type, 1},
                          {tx_fd, flow_ifname, DHCP_MESSAGE_TYPE_NAK, 1}}, DHCP_MON_STATUS_UNHEALTHY});
        cases.push_back({name + " v4 management TX", mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE,
                         {{tx_fd, mgmt_ifname, msg_type, 1}}, DHCP_MON_STATUS_UNHEALTHY});
    }
    for (dhcpv6_message_type_t msg_type : excluded_path_msgs_v6) {
        const std::string name = db_counter_name_v6[msg_type];
        cases.push_back({name + " does not wake v4 positive health", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE,
                         {{rx_fd_v6, flow_ifname, msg_type, 1}}, DHCP_MON_STATUS_INDETERMINATE});
        cases.push_back({name + " does not wake v4 negative health", mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE,
                         {{tx_fd_v6, mgmt_ifname, msg_type, 1}}, DHCP_MON_STATUS_INDETERMINATE});
    }
    cases.push_back({"legacy v6 activity still wakes v4 positive health", flow_ifname, DHCP_DEVICE_CHECK_POSITIVE,
                     {{rx_fd_v6, flow_ifname, DHCPV6_MESSAGE_TYPE_SOLICIT, 1}}, DHCP_MON_STATUS_HEALTHY});
    cases.push_back({"legacy v6 activity still wakes v4 negative health", mgmt_ifname, DHCP_DEVICE_CHECK_NEGATIVE,
                     {{rx_fd_v6, mgmt_ifname, DHCPV6_MESSAGE_TYPE_SOLICIT, 1}}, DHCP_MON_STATUS_HEALTHY});
    cases.push_back({"v4 VLAN TX permits member fanout", parent_ifname, DHCP_DEVICE_CHECK_AGG_TX,
                     {{tx_fd, parent_ifname, DHCP_MESSAGE_TYPE_DISCOVER, 1},
                      {tx_fd, member_agg_ifname, DHCP_MESSAGE_TYPE_DISCOVER, 2}}, DHCP_MON_STATUS_HEALTHY});
    cases.push_back({"v4 VLAN TX rejects excess member fanout", parent_ifname, DHCP_DEVICE_CHECK_AGG_TX,
                     {{tx_fd, parent_ifname, DHCP_MESSAGE_TYPE_DISCOVER, 1},
                      {tx_fd, member_agg_ifname, DHCP_MESSAGE_TYPE_DISCOVER, 3}}, DHCP_MON_STATUS_UNHEALTHY});
    cases.push_back({"v4 VLAN RX retains exact matching", parent_ifname, DHCP_DEVICE_CHECK_AGG_RX,
                     {{rx_fd, parent_ifname, DHCP_MESSAGE_TYPE_DISCOVER, 1},
                      {rx_fd, member_agg_ifname, DHCP_MESSAGE_TYPE_DISCOVER, 2}}, DHCP_MON_STATUS_UNHEALTHY});
    cases.push_back({"v4 PortChannel TX retains exact matching", "PortChannel1", DHCP_DEVICE_CHECK_AGG_TX,
                     {{tx_fd, "PortChannel1", DHCP_MESSAGE_TYPE_DISCOVER, 1},
                      {tx_fd, "Agg-PortChannel1", DHCP_MESSAGE_TYPE_DISCOVER, 2}}, DHCP_MON_STATUS_UNHEALTHY});
    return cases;
}

/**
 * @brief Evaluate the real public health API and report a named failure without relying on assert().
 */
static bool expect_status(const health_case_t &test, dhcp_mon_status_t expected, const char *phase)
{
    const dhcp_mon_status_t actual = dhcp_device_get_status(test.ifname, test.check_type);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s (%s, check %d, interface %s): expected %d, got %d\n",
                test.name.c_str(), phase, test.check_type, test.ifname.c_str(), expected, actual);
        return false;
    }
    return true;
}

/**
 * @brief Run isolated counter-delta cases and verify that real snapshots return every case to idle.
 */
int main()
{
    try {
        const std::vector<health_case_t> cases = make_cases();
        size_t failures = 0;
        for (const health_case_t &test : cases) {
            initialize_counters();
            for (const counter_change_t &change : test.changes) {
                sock_mgr_get_sock_info(change.sock).all_counters.at(change.ifname).at(change.msg_type) += change.delta;
            }
            failures += !expect_status(test, test.expected, "counter delta");
            sock_mgr_update_snapshot();
            failures += !expect_status(test, DHCP_MON_STATUS_INDETERMINATE, "after snapshot");
        }
        if (failures != 0) {
            fprintf(stderr, "%zu health-accounting checks failed\n", failures);
            return EXIT_FAILURE;
        }
        printf("Passed %zu health-accounting cases and their snapshot checks\n", cases.size());
    } catch (const std::exception &error) {
        fprintf(stderr, "Health-accounting test failed: %s\n", error.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
