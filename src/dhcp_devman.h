/**
 * @file dhcp_devman.h
 *
 * Device (interface) manager
 * 
 * Collection of functions to manage all the interfaces information and their roles, their relations to each other, and operations on
 * all interfaces. Functions are noop on failure.
 * 
 * dhcp_devman_add_intf and dhcp_devman_setup_dual_tor_mode will be called during command line arg processing, before dhcp_devman_init
 * dhcp_devman_init will initialize all interfaces added, and dhcp_devman_free will clean up all allocated resources
 * dhcp_devman_init and dhcp_devman_free will be called by dhcp_mon
 * dhcp_devman_get_status, dhcp_devman_print_status are interface to dhcp_device functions
 */

#ifndef DHCP_DEVMAN_H_
#define DHCP_DEVMAN_H_

#include <string>
#include <unordered_map>
#include <unordered_set>

#include "dhcp_device.h"

/** if we are in dual tor mode */
extern bool dual_tor_mode;

/** address families monitored for the downstream VLAN */
extern bool dhcpv4_enabled;
extern bool dhcpv6_enabled;

/** ip information for downstream vlan interface */
extern in_addr vlan_ip;
extern in6_addr vlan_ipv6_gua;
extern in6_addr vlan_ipv6_lla;

/** loopback interface ip, which will be used as the giaddr in dual tor setup. */
extern in_addr loopback_ip;
extern in6_addr loopback_ipv6_gua;

/** gateway ip in dhcp, used to filter packets that pertain to our downstream vlan interface */
extern in_addr giaddr_ip;
extern in_addr zero_ip;
extern in6_addr giaddr_ipv6_gua;
extern in6_addr zero_ipv6;

extern in_addr broadcast_ip;
extern in6_addr dhcpv6_multicast_ipv6;

/** downstream interface name */
extern std::string downstream_ifname;

/** mgmt interface name */
extern std::string mgmt_ifname;

/** aggregate interface of all except mgmt to track overall packet flow for host */
extern std::string agg_dev_all;
extern std::string agg_dev_prefix;

/* interface to vlan mapping */
extern std::unordered_map<std::string, std::string> vlan_map;

/* interface to port-channel mapping */
extern std::unordered_map<std::string, std::string> portchan_map;

/* vlan to interface mapping */
extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_vlan_map;

/* port-channel to interface mapping */
extern std::unordered_map<std::string, std::unordered_set<std::string>> rev_portchan_map;

/** name to context struct map for all context interface only */
extern std::unordered_map<std::string, dhcp_device_context_t *> intfs;

/**
 * @code dhcp_devman_add_intf(name, intf_type);
 *
 * @brief adds interface to the device manager.
 *
 * @param name              interface name
 * @param intf_type         'u' for uplink (north) interface
 *                          'd' for downlink (south) interface
 *                          'm' for mgmt interface
 *
 * @return 0 on success, negative otherwise
 */
int dhcp_devman_add_intf(const char *name, char intf_type);

/**
 * @code dhcp_devman_setup_dual_tor_mode(name);
 *
 * @brief set up dual tor mode: 1) set dual_tor_mode flag and 2) retrieve loopback_ip.
 *
 * @param name              interface name
 *
 * @return 0 on success, negative otherwise
 */
int dhcp_devman_setup_dual_tor_mode(const char *name);

/**
 * @code dhcp_devman_is_tracked_interface(ifname);
 *
 * @brief checks whether the given interface name is being tracked by dhcp device manager,
 *        either as a context interface, or as a member of a context interface.
 *
 * @param ifname            interface name
 *
 * @return true if tracked, false otherwise
 */
bool dhcp_devman_is_tracked_interface(const std::string &ifname);

/**
 * @code dhcp_devman_init(snaplen);
 *
 * @brief initializes the device manager, validates interface counts, and enables the downstream VLAN address families
 *
 * @return 0 on success, negative otherwise
 */
int dhcp_devman_init();

/**
 * @code dhcp_devman_free();
 *
 * @brief  frees resources used by device (interface) manager and undo init. Not only undo dhcp_devman_init but also all the add 
 *         interfaces memory
 *
 * @return none
 */
void dhcp_devman_free();

/**
 * @code dhcp_devman_get_parent_ifname(ifname);
 *
 * @brief find the immediate parent interface of a tracked interface.
 *
 * @param ifname           interface name
 *
 * @return Immediate parent interface name, or an empty string when the interface is a tracked root or is unmapped
 */
std::string dhcp_devman_get_parent_ifname(const std::string &ifname);

/**
 * @code dhcp_devman_get_device_context(ifname);
 *
 * @brief find the tracked input interface that owns an interface.
 *
 * @param ifname           interface name
 *
 * @return The interface's tracked context; a tracked input interface returns its own context
 */
const dhcp_device_context_t* dhcp_devman_get_device_context(const std::string &ifname);

/**
 * @code dhcp_devman_get_agg_counter_ifname(ifname);
 *
 * @brief find the aggregate counter updated by an interface observation.
 *
 * @param ifname           interface name
 *
 * @return immediate-parent aggregate, or the root aggregate when no parent exists
 */
std::string dhcp_devman_get_agg_counter_ifname(const std::string &ifname);

/**
 * @code dhcp_devman_print_all_status(type);
 *
 * @brief prints status counters for all interfaces to syslog.
 *
 * @param type              counter type
 *
 * @return none
 */
void dhcp_devman_print_all_status(dhcp_counters_type_t type);

/**
 * @code dhcp_devman_print_all_status_debug(type);
 *
 * @brief same as dhcp_devman_print_all_status but only print when debug_on is true
 *
 * @param type              counter type
 *
 * @return none
 */
void dhcp_devman_print_all_status_debug(dhcp_counters_type_t type);

#endif /* DHCP_DEVMAN_H_ */
