#include <string>
#include <unordered_map>   

/**
 * DHCP message types
 **/
typedef enum
{
    DHCP_MESSAGE_TYPE_DISCOVER = 1,
    DHCP_MESSAGE_TYPE_OFFER    = 2,
    DHCP_MESSAGE_TYPE_REQUEST  = 3,
    DHCP_MESSAGE_TYPE_DECLINE  = 4,
    DHCP_MESSAGE_TYPE_ACK      = 5,
    DHCP_MESSAGE_TYPE_NAK      = 6,
    DHCP_MESSAGE_TYPE_RELEASE  = 7,
    DHCP_MESSAGE_TYPE_INFORM   = 8,

    DHCP_MESSAGE_TYPE_COUNT
} dhcp_message_type_t;

extern std::string db_counter_name[DHCP_MESSAGE_TYPE_COUNT];

std::string generate_json_string(const std::unordered_map<uint8_t, uint64_t>* counter);
