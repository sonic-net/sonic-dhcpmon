#include <arpa/inet.h>
#include <swss/dbconnector.h>
#include <swss/table.h>
#include "src/util.h"
#include <cassert>
#include <array>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <vector>
std::shared_ptr<swss::DBConnector> mStateDbPtr;
std::shared_ptr<swss::Table> mStateDbMuxTablePtr;
std::mutex mux_table_lock;
std::shared_ptr<swss::DBConnector> mConfigDbPtr;
bool dual_tor_mode = false;
std::string downstream_ifname = "Vlan1000";
static uint32_t reference_sum(const uint8_t *p, size_t n) {
    uint32_t sum=0; for(size_t i=0;i<n;i+=2) sum += (uint16_t(p[i])<<8) | (i+1<n?p[i+1]:0); return sum;
}
static uint16_t reference_fold(uint32_t n) { while(n>>16)n=(n&65535)+(n>>16); return uint16_t(~n); }
int main() {
    std::array<uint8_t,65> bytes{}; for(size_t i=0;i<bytes.size();++i)bytes[i]=uint8_t(i*37+11);
    for(size_t n=0;n<=bytes.size();++n)assert(checksum_accumulate_words(bytes.data(),n)==reference_sum(bytes.data(),n));
    std::cout << "PASS checksum lengths 0..65\n";
    for(uint32_t n: {0u,1u,65535u,65536u,0x12345678u,0xffffffffu})assert(checksum_finalize_fold(n)==reference_fold(n));
    std::cout << "PASS carry folding\n";
    iphdr ip{};ip.version=4;ip.ihl=5;ip.ttl=64;ip.protocol=17;inet_pton(AF_INET,"192.0.2.1",&ip.saddr);inet_pton(AF_INET,"198.51.100.2",&ip.daddr);
    assert(calculate_ip_checksum(&ip)==reference_fold(reference_sum(reinterpret_cast<uint8_t*>(&ip),20)));assert(calculate_ip_checksum(nullptr)==0);
    std::cout << "PASS IPv4 header checksum\n";
    struct {udphdr header;uint8_t payload[7];} udp{};udp.header.source=htons(67);udp.header.dest=htons(68);udp.header.len=htons(15);for(int i=0;i<7;++i)udp.payload[i]=uint8_t(i+1);
    uint32_t sum=reference_sum(reinterpret_cast<uint8_t*>(&ip.saddr),4)+reference_sum(reinterpret_cast<uint8_t*>(&ip.daddr),4)+17+15+reference_sum(reinterpret_cast<uint8_t*>(&udp),15);
    uint16_t wanted=reference_fold(sum);if(!wanted)wanted=65535;assert(calculate_udp_checksum(&udp.header,reinterpret_cast<uint8_t*>(&ip),false)==wanted);
    udp.header.check=htons(wanted);assert(calculate_udp_checksum(&udp.header,reinterpret_cast<uint8_t*>(&ip),false)==65535);udp.header.check=0;
    std::cout << "PASS IPv4 UDP pseudoheader and zero checksum encoding\n";
    ip6_hdr ip6{};inet_pton(AF_INET6,"2001:db8::1",&ip6.ip6_src);inet_pton(AF_INET6,"2001:db8::2",&ip6.ip6_dst);
    sum=reference_sum(reinterpret_cast<uint8_t*>(&ip6.ip6_src),16)+reference_sum(reinterpret_cast<uint8_t*>(&ip6.ip6_dst),16)+17+15+reference_sum(reinterpret_cast<uint8_t*>(&udp),15);
    wanted=reference_fold(sum);if(!wanted)wanted=65535;assert(calculate_udp_checksum(&udp.header,reinterpret_cast<uint8_t*>(&ip6),true)==wanted);assert(calculate_udp_checksum(nullptr,reinterpret_cast<uint8_t*>(&ip6),true)==0);assert(calculate_udp_checksum(&udp.header,nullptr,false)==0);
    std::cout << "PASS IPv6 UDP pseudoheader and invalid pointer handling\n";
    uint64_t number=0;assert(parse_uint64_from_str("0",number)&&number==0);assert(parse_uint64_from_str("18446744073709551615",number)&&number==std::numeric_limits<uint64_t>::max());assert(!parse_uint64_from_str("18446744073709551616",number));assert(!parse_uint64_from_str("12junk",number));assert(!parse_uint64_from_str("",number));
    std::cout << "PASS uint64 parsing boundaries\n";
    std::string valid="{\"a\":1,\"b\":\"relay\"}",invalid="{broken";Json::Value value;assert(parse_json_str(&valid,&value));assert(value["a"].asInt()==1&&value["b"].asString()=="relay");assert(!parse_json_str(&invalid,&value));assert(!parse_json_str(&valid,nullptr));
    std::cout << "PASS production JSON parsing\n";
    std::array<uint8_t,6> mac{0,17,34,51,68,255};assert(generate_addr_string(mac.data(),6)=="00:11:22:33:44:ff");assert(generate_addr_string(reinterpret_cast<uint8_t*>(&ip.saddr),4)=="192.0.2.1");in6_addr loop{};inet_pton(AF_INET6,"::1",&loop);assert(generate_addr_string(reinterpret_cast<uint8_t*>(&loop),16)=="::1");
    std::cout << "PASS IPv4 IPv6 and MAC formatting\n";
    auto own=construct_counter_db_table_key("Vlan1000",false),other=construct_counter_db_table_key("Ethernet0",false),v6=construct_counter_db_table_key("Ethernet0",true);assert(own==std::string(COUNTERS_DB_COUNTER_TABLE_PREFIX)+"Vlan1000");assert(other==std::string(COUNTERS_DB_COUNTER_TABLE_PREFIX)+"Vlan1000"+COUNTERS_DB_SEPARATOR+"Ethernet0");assert(v6==std::string(COUNTERS_DB_COUNTER_TABLE_V6_PREFIX)+"Vlan1000"+COUNTERS_DB_SEPARATOR+"Ethernet0");assert(parse_counter_table_key(other)==std::make_pair(std::string("Vlan1000"),std::string("Ethernet0")));assert(parse_counter_table_key(own)==std::make_pair(std::string("Vlan1000"),std::string("Vlan1000")));assert(!intf_is_standby("Ethernet0"));
    std::cout << "PASS counter keys and non-dual-ToR standby path\n";
    std::string names[]={"discover","offer"};std::unordered_map<uint8_t,uint64_t> counters{{0,1},{1,2}};assert(generate_json_string(&counters,2,names)=="{'discover':'1','offer':'2'}");assert(generate_json_string(nullptr,2,names)=="{'discover':'0','offer':'0'}");
    std::cout << "PASS counter serialization\nMonitor-production-utility-PASS 10 groups\n";
}
