#include <string>
#include <memory>
#include <jsoncpp/json/json.h>
#include <syslog.h>
#include <unordered_map>

#define COUNTERS_DB_COUNTER_TABLE_PREFIX "DHCPV4_COUNTER_TABLE:"
#define STATE_DB_COUNTER_UPDATE_PREFIX "DHCPV4_COUNTER_UPDATE|"
#define COUNTERS_DB_SEPARATOR ":"

extern std::string downstream_if_name;


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
