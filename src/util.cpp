#include "util.h"


/**
 * @code  construct_counter_db_table_key(const std::string &ifname);
 * @brief Function to construct key in counters_db
 * @param ifname       interface name
 * @return string of counters_db key
 */
std::string construct_counter_db_table_key(const std::string &ifname) {
    std::string key;
    if (downstream_if_name.compare(ifname) != 0) {
       key = COUNTERS_DB_COUNTER_TABLE_PREFIX + downstream_if_name + COUNTERS_DB_SEPARATOR + ifname;
    } else {
       key = COUNTERS_DB_COUNTER_TABLE_PREFIX + ifname;
    }
    return key;
}

/**
 * @code  parse_json_str(const std::string *json_str, Json::Value* out_value);
 * @brief Function to parse json string
 * @param json_str       json string need to be parsed
 * @param out_value      Json obj to store parsing result
 * @return bool indicate parsing result
 */
bool parse_json_str(const std::string *json_str, Json::Value* out_value) {
    if (!out_value) {
        syslog(LOG_WARNING, "Pointer of out_value is NULL\n");
        return false;
    }

    Json::CharReaderBuilder builder;
    JSONCPP_STRING err;

    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    auto json_begin = json_str->c_str();
    auto json_end = json_begin + json_str->length();
    if (reader->parse(json_str->c_str(), json_end, out_value, &err)) {
        return true;
    } else {
        syslog(LOG_WARNING, "Failed to parse json str: %s, %s\n", json_begin, err.c_str());
        return false;
    }
}

/**
 * @code  parse_uint64_from_str(const std::string& str, uint64_t& result);
 * @brief Function to parse uint64 from string
 * @param str            string need to be parsed
 * @param result         int referrence to store parsing result
 * @return bool indicate parsing result
 */
bool parse_uint64_from_str(const std::string& str, uint64_t& result) {
    try {
        size_t idx = 0;
        result = std::stoull(str, &idx);
        return idx == str.size();
    } catch (const std::exception& e) {
        syslog(LOG_ALERT, "Failed to parse uint64_t from string '%s': %s", str.c_str(), e.what());
        return false;
    }
}
