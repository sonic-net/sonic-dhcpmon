#include <arpa/inet.h>
#include <syslog.h>

#include "util.h"
#include <swss/subscriberstatetable.h>

thread_local bool debug_mask = true;

bool debug_on = false;

extern std::shared_ptr<swss::DBConnector> mStateDbPtr;
extern std::shared_ptr<swss::Table> mStateDbMuxTablePtr;
extern std::shared_ptr<swss::DBConnector> mConfigDbPtr;

extern bool dual_tor_mode;
extern std::string downstream_ifname;

struct udp_pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_length;
};

struct udp6_pseudo_header {
    struct in6_addr src_addr;     // 128-bit source IPv6 address
    struct in6_addr dst_addr;     // 128-bit destination IPv6 address
    uint32_t udp_length;          // Length of UDP header + payload
    uint8_t zero[3];              // Three bytes of zero padding
    uint8_t next_header;          // Protocol number (17 for UDP)
};

bool addr_is_primary(const std::string &ifname, const in_addr *addr)
{
    auto match_pattern = std::string("*INTERFACE|" + ifname + "|*");
    auto keys = mConfigDbPtr->keys(match_pattern);

    for (const auto &key : keys) {
        auto last_of_bar = key.find_last_of('|');
        auto last_of_slash = key.find_last_of('/');
        if (last_of_bar == std::string::npos || last_of_slash == std::string::npos || last_of_bar >= last_of_slash) {
            continue;
        }
        auto addr_str = key.substr(last_of_bar + 1, last_of_slash - last_of_bar - 1);
        struct in_addr curr_addr;
        if (inet_pton(AF_INET, addr_str.c_str(), &curr_addr) == 1 && curr_addr.s_addr == addr->s_addr) {
            auto val = mConfigDbPtr->hget(key, "secondary");
            return val == NULL || *val == "false";
        } else {
            continue;
        }
    }

    return true;
}

bool intf_is_standby(const std::string &ifname)
{
    if (dual_tor_mode) {
        std::string state;
        mStateDbMuxTablePtr->hget(ifname, "state", state);
        return state == "standby";
    }
    return false;
}

std::string construct_counter_db_table_key(const std::string &ifname, bool is_v6) {
    std::string key = is_v6 ? COUNTERS_DB_COUNTER_TABLE_V6_PREFIX : COUNTERS_DB_COUNTER_TABLE_PREFIX;
    if (downstream_ifname.compare(ifname) != 0) {
       key += downstream_ifname + COUNTERS_DB_SEPARATOR + ifname;
    } else {
       key += ifname;
    }
    return key;
}

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

std::pair<std::string, std::string> parse_counter_table_key(const std::string& key) {
    std::string vlan;
    std::string interface;
    auto first = key.find_first_of(COUNTERS_DB_SEPARATOR);
    auto last = key.find_last_of(COUNTERS_DB_SEPARATOR);
    if (first == last) {
        // Vlan interfaces
        interface = key.substr(first + 1, key.length() - first);
        vlan = key.substr(first + 1, key.length() - first);
    } else {
        // Physical interfaces
        interface = key.substr(last + 1, key.length() - last);
        vlan = key.substr(first + 1, last - first - 1);
    }
    return std::make_pair(vlan, interface);
}

uint32_t checksum_accumulate_words(const uint8_t *data, size_t length) {
    uint32_t sum = 0;
    size_t i = 0;

    while (i + 8 <= length) {
        sum += (uint16_t)((data[i] << 8) | data[i + 1]);
        sum += (uint16_t)((data[i + 2] << 8) | data[i + 3]);
        sum += (uint16_t)((data[i + 4] << 8) | data[i + 5]);
        sum += (uint16_t)((data[i + 6] << 8) | data[i + 7]);
        i += 8;
    }

    if (i + 4 <= length) {
        sum += (uint16_t)((data[i] << 8) | data[i + 1]);
        sum += (uint16_t)((data[i + 2] << 8) | data[i + 3]);
        i += 4;
    }

    if (i + 2 <= length) {
        sum += (uint16_t)((data[i] << 8) | data[i + 1]);
        i += 2;
    }

    if (i < length) {
        sum += (uint16_t)(data[i] << 8);
    }
    return sum;

}

uint16_t checksum_finalize_fold(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

uint16_t calculate_ip_checksum(const struct iphdr *iphdr) {
    if (!iphdr) {
        return 0;  // Invalid IP header
    }
    return checksum_finalize_fold(checksum_accumulate_words((const uint8_t *)iphdr, iphdr->ihl * 4));
}

/**
 * Compute the UDP pseudo-header checksum for IPv4 and IPv6.
 * @param iphdr     Pointer to the IP header.
 * @param udphdr   Pointer to the UDP header.
 * @return          The computed UDP pseudo-header checksum.
 */
static uint32_t calculate_udp_pseudo_header_ip(const struct iphdr *iphdr, const struct udphdr *udphdr) {
    struct udp_pseudo_header uph;
    memset(&uph, 0, sizeof(uph));

    uph.src_addr = iphdr->saddr;
    uph.dst_addr = iphdr->daddr;
    uph.protocol = IPPROTO_UDP;
    uph.udp_length = udphdr->len;

    return checksum_accumulate_words((uint8_t *)&uph, sizeof(uph));
}

/**
 * Compute the UDP pseudo-header checksum for IPv6.
 * @param ip6hdr     Pointer to the IPv6 header.
 * @param udphdr   Pointer to the UDP header.
 * @return          The computed UDP pseudo-header checksum.
 */
static uint32_t calculate_udp_pseudo_header_ipv6(const struct ip6_hdr *ip6hdr, const struct udphdr *udphdr) {
    struct udp6_pseudo_header uph;
    memset(&uph, 0, sizeof(uph));

    uph.src_addr = ip6hdr->ip6_src;
    uph.dst_addr = ip6hdr->ip6_dst;
    uph.udp_length = udphdr->len;
    uph.next_header = IPPROTO_UDP;

    return checksum_accumulate_words((uint8_t *)&uph, sizeof(uph));
}

uint16_t calculate_udp_checksum(const struct udphdr *udphdr, const uint8_t *data, bool is_v6) {
    if (!udphdr || !data) {
        return 0;  // Invalid arguments
    }

    uint32_t sum = is_v6 ? calculate_udp_pseudo_header_ipv6((const struct ip6_hdr *)data, udphdr) : calculate_udp_pseudo_header_ip((const struct iphdr *)data, udphdr);
    sum += checksum_accumulate_words((const uint8_t *)udphdr, (uint16_t)ntohs(udphdr->len));
    uint16_t final_sum = checksum_finalize_fold(sum);

    return final_sum == 0 ? 0xFFFF : final_sum;
}

std::string generate_json_string(const std::unordered_map<uint8_t, uint64_t> *counter, int message_type_count, const std::string *db_counter_name) {
    std::string res;
    res.reserve(300);
    res.append("{");
    for (int i = 0; i < message_type_count; i++) {
        std::string value = std::to_string(counter == NULL ? 0 : counter->at(i));
        std::string json_value = "'" + db_counter_name[i] + "':'" + value + "'";
        res.append(json_value);
        if (i < message_type_count - 1) {
            res.append(",");
        }
    }
    res.append("}");
    return res;
}

std::string generate_addr_string(const uint8_t *addr, size_t addr_len) {
    std::string addr_str;
    
    switch (addr_len) {
        case 4: {
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, addr, buf, sizeof(buf));
            addr_str = buf;
            break;
        }
        case 6: {
            char buf[18];
            snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                     addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
            addr_str = buf;
            break;
        }
        case 16: {
            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, addr, buf, sizeof(buf));
            addr_str = buf;
            break;
        }
        default: {
            size_t out_size = addr_len * 3 + 1;
            char *buf = (char *)malloc(out_size);
            if (buf == NULL) {
                break;
            }
            for (size_t i = 0; i < addr_len; ++i) {
                snprintf(buf + i * 3, out_size - i * 3, "%02X ", addr[i]);
            }
            buf[out_size - 1] = '\0';
            addr_str = buf;
            free(buf);
            break;
        }
    }

    return addr_str;
}