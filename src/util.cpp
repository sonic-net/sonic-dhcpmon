#include "util.h"


std::string generate_json_string(const std::unordered_map<uint8_t, uint64_t>* counter) {
    std::string res;
    res.reserve(300);
    res.append("{");
    for (int i = 0; i < DHCP_MESSAGE_TYPE_COUNT; i++) {
        auto value = std::to_string(counter == nullptr ? 0 : counter->at(i));
        auto json_value = "'" + db_counter_name[i] + "':'" + value + "'";
        res.append(json_value);
        if (i < DHCP_MESSAGE_TYPE_COUNT - 1) {
            res.append(",");
        }
    }
    res.append("}");
    return res;
}