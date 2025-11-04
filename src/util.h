
#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <memory>
#include <jsoncpp/json/json.h>
#include <syslog.h>
#include <unordered_map>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <event2/event.h>

#define COUNTERS_DB_COUNTER_TABLE_PREFIX "DHCPV4_COUNTER_TABLE:"
#define COUNTERS_DB_COUNTER_TABLE_V6_PREFIX "DHCPV6_COUNTER_TABLE:"
#define STATE_DB_COUNTER_UPDATE_PREFIX "DHCPV4_COUNTER_UPDATE|"
#define STATE_DB_COUNTER_UPDATE_V6_PREFIX "DHCPV6_COUNTER_UPDATE|"
#define COUNTERS_DB_SEPARATOR ":"

/** a threadlocal debug mask for debug_on, sometimes we want to print less even though debug is on */
/** it is used like debug_on && debug_mask, so when mask is false, debug_on is essentially false */
extern thread_local bool debug_mask;

/** dhcpmon debug mode control flag, mostly used for logging for more frequent operations */
extern bool debug_on;

extern std::string agg_dev_prefix;
extern std::string agg_dev_all;

/**
 * @code addr_is_primary(ifname, addr);
 *
 * @brief helper function check if address is primary on the interface,
 * Config db might have a secondary tag on some addresses, which means they are not primary
 * and if not found, default is primary
 *
 * @return boolean
 */
bool addr_is_primary(const std::string &ifname, const in_addr *addr);

/**
 * @code intf_is_standby(intf);
 *
 * @brief helper function check if interface is standby
 *
 * @return boolean
 */
bool intf_is_standby(const std::string &ifname);

/**
 * @code  construct_counter_db_table_key(ifname, is_v6);
 * @brief Function to construct key in counters_db, only add downstream prefix for non-downstream interface
 * @param ifname       interface name
 * @param is_v6        whether it's for DHCPv6
 * @return string of counters_db key
 */
std::string construct_counter_db_table_key(const std::string &ifname, bool is_v6);

/**
 * @code  parse_json_str(json_str, out_value);
 * @brief Function to parse json string
 * @param json_str       json string need to be parsed
 * @param out_value      Json obj to store parsing result
 * @return bool indicate parsing result
 */
bool parse_json_str(const std::string *json_str, Json::Value *out_value);

/**
 * @code  parse_uint64_from_str(str, result);
 * @brief Function to parse uint64 from string
 * @param str            string need to be parsed
 * @param result         int referrence to store parsing result
 * @return bool indicate parsing result
 */
bool parse_uint64_from_str(const std::string &str, uint64_t &result);

/**
 * @code  parse_counter_table_key(key);
 * @brief Function to parse key in counters_db
 * @param key            key in counter table
 * @return               pair of vlan and interface strings
 */
std::pair<std::string, std::string> parse_counter_table_key(const std::string &key);

/**
 * @code  checksum_accumulate_words(data, length);
 * @brief Compute the accumulate checksum for a given data buffer without final fold.
 * @param data     Pointer to the data buffer.
 * @param length  Length of the data buffer.
 * @return       The computed partial checksum.
 */
uint32_t checksum_accumulate_words(const uint8_t *data, size_t length);

/**
 * @code  checksum_finalize_fold(sum);
 * @brief Finalize and fold the accumulated checksum to 16 bits.
 * @param sum      The accumulated checksum.
 * @return        The finalized 16-bit checksum.
 */
uint16_t checksum_finalize_fold(uint32_t sum);

/**
 * @code  calculate_ip_checksum(iphdr);
 * @brief Compute the IP header checksum for a given IP header.
 * @param iphdr     Pointer to the IP header.
 * @return          The computed IP header checksum.
 */
uint16_t calculate_ip_checksum(const struct iphdr *iphdr);

/**
 * @code  calculate_udp_checksum(udphdr, data, is_v6);
 * @brief Compute the UDP checksum for a given IP header and UDP packet(including header and payload).
 * @param udphdr     Pointer to the UDP header.
 * @param data       Pointer to the whole packet buffer (including IP header).
 * @param is_v6      True if the packet is IPv6, false if IPv4
 * @return          The computed UDP checksum.
 */
uint16_t calculate_udp_checksum(const struct udphdr *udphdr, const uint8_t *data, bool is_v6);

/**
 * @code                generate_json_string(counter, message_type_count, db_counter_name);
 * @brief               Generate JSON string by counter dict
 * @param counter             Counter dict
 * @param message_type_count  Number of message types
 * @param db_counter_name     Array of counter names
 * @return              generated JSON string
 */
std::string generate_json_string(const std::unordered_map<uint8_t, uint64_t>* counter, int message_type_count, const std::string *db_counter_name);

/**
 * @code                generate_addr_string(addr, addr_len);
 * @brief               Generate string representation of an IP address, MAC address, or other binary data
 * @param addr          Pointer to the IP address
 * @param addr_len      Length of the IP address (4 for IPv4, 16 for IPv6)
 * @return              generated address string
 */
std::string generate_addr_string(const uint8_t *addr, size_t addr_len);

/**
 * @code                zero_out_counter(counter);
 * @brief               Helper function to zero out all entries in a counter
 * @param counter       Counter to be zeroed out
 */
template <typename Key, typename Value>
void zero_out_counter(std::unordered_map<Key, Value> &map)
{
    for (auto& [_, value] : map) {
        value = Value{};
    }
}

/**
 * @code                readonly_access(map, key, default_value);
 * @brief               Helper function to provide read-only access to unordered_map with default value support
 * @param map           The unordered_map to access
 * @param key           The key to look for
 * @param default_value The default value to return if the key is not found
 * @return              The value associated with the key, or the default value if the key is not found
 */
template <typename Key, typename Value>
const Value& readonly_access(const std::unordered_map<Key, Value>& map, const Key& key, const Value& default_value=Value())
{
    auto it = map.find(key);
    if (it != map.end()) {
        return it->second;
    }
    return default_value;
}

/**
 * @code                is_agg_counter(ifname);
 * @brief               Check if the given ifname is an aggregate counter
 * @param ifname        Interface name
 * @return              true if it is an aggregate counter, false otherwise
 */
inline bool is_agg_counter(const std::string &ifname)
{
    return ifname.compare(0, agg_dev_prefix.size(), agg_dev_prefix) == 0 || ifname == agg_dev_all;
}

/**
 * @code                get_agg_counter_ifname(ifname, context);
 * @brief               Get aggregate counter name for given ifname and device context
 * @param ifname        Interface name
 * @param context       Pointer to device context
 * @return              Aggregate counter name
 */
inline std::string get_agg_counter_ifname(const std::string &ifname, const std::string &context_ifname)
{
    return ifname != context_ifname ? agg_dev_prefix + context_ifname : agg_dev_all;
}

/**
 * @code                syslog_debug(priority, format, ...);
 * @brief               Log debug messages to syslog if debug_on is true
 * @param priority      Syslog priority level
 * @param format        Format string for the log message
 * @param ...           Additional arguments for the format string
 */
inline void syslog_debug(int priority, const char *format, ...)
{
    if (debug_on && debug_mask) {
        va_list args;
        va_start(args, format);
        vsyslog(priority, format, args);
        va_end(args);
    }
}

#endif //UTIL_H
