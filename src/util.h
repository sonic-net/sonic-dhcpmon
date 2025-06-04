
#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <memory>
#include <jsoncpp/json/json.h>
#include <syslog.h>
#include <unordered_map>
#include <event2/event.h>

#define COUNTERS_DB_COUNTER_TABLE_PREFIX "DHCPV4_COUNTER_TABLE:"
#define STATE_DB_COUNTER_UPDATE_PREFIX "DHCPV4_COUNTER_UPDATE|"
#define COUNTERS_DB_SEPARATOR ":"

extern std::string downstream_if_name;

/** packet direction */
typedef enum
{
    DHCP_RX,    /** RX DHCP packet */
    DHCP_TX,    /** TX DHCP packet */

    DHCP_DIR_COUNT
} dhcp_packet_direction_t;

/** string case type */
typedef enum
{
    UPPER_CASE,
    LOWER_CASE
} str_case_type;

/**
 * @code  construct_counter_db_table_key(const std::string &ifname);
 * @brief Function to construct key in counters_db
 * @param ifname       interface name
 * @return string of counters_db key
 */
std::string construct_counter_db_table_key(const std::string &ifname);

/**
 * @code  parse_json_str(const std::string *json_str, Json::Value* out_value);
 * @brief Function to parse json string
 * @param json_str       json string need to be parsed
 * @param out_value      Json obj to store parsing result
 * @return bool indicate parsing result
 */
bool parse_json_str(const std::string *json_str, Json::Value* out_value);

/**
 * @code  parse_uint64_from_str(const std::string& str, uint64_t& result);
 * @brief Function to parse uint64 from string
 * @param str            string need to be parsed
 * @param result         int referrence to store parsing result
 * @return bool indicate parsing result
 */
bool parse_uint64_from_str(const std::string& str, uint64_t& result);

/**
 * @code  gen_dir_str(const dhcp_packet_direction_t& dir, const str_case_type case_type);
 * @brief Function to generate dir string
 * @param dir            direction, DHCP_RX or DHCP_TX
 * @param case_type      UPPER_CASE or LOWER_CASE
 * @return string of direction
 */
std::string gen_dir_str(const dhcp_packet_direction_t& dir, const str_case_type case_type);

/**
 * @code void parse_counter_table_key(std::string& vlan, std::string& interface);
 * @brief Function to parse key in counters_db
 * @param key            key in counter table
 * @param vlan           reference of parsed vlan string
 * @param interface      reference of parsed interface string
 */
void parse_counter_table_key(std::string& key, std::string& vlan, std::string& interface);

/**
 * @code void event_init_check_and_free(struct event *current_event);
 * @brief Check whether event is NULL and re-init it
 * @param current_event  point of event
 */
void event_init_check_and_free(struct event *current_event);

#endif //UTIL_H
