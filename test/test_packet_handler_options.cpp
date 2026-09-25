/**
 * @file test_packet_handler_options.cpp
 *
 * Unit tests for the DHCP / DHCPv6 option walkers in src/packet_handler.cpp.
 *
 * The walkers are file-static, so the implementation translation unit is
 * included directly and the handful of symbols it refers to are stubbed below.
 * Every option buffer handed to a walker is allocated to its exact length, so
 * a read of even one byte past the options area is caught by AddressSanitizer.
 *
 * Build and run via:  make -f test/Makefile test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

/* ------------------------------------------------------------------ *
 * Stubs for symbols referenced by packet_handler.cpp.
 * These tests exercise the pure option-parsing logic only, so the
 * socket, counter and topology machinery is replaced with inert stand-ins.
 * ------------------------------------------------------------------ */

#include "src/dhcp_device.h"
#include "src/dhcp_check_profile.h"
#include "src/sock_mgr.h"
#include "src/dhcp_devman.h"

bool debug_on = false;
thread_local bool debug_mask = true;
bool dual_tor_mode = false;
std::string mgmt_ifname;
std::string agg_dev_prefix = "Agg-";
std::string agg_dev_all = "Agg-All";

const char *intf_type_name[DHCP_DEVICE_INTF_TYPE_COUNT] = { "uplink", "downlink", "mgmt" };

dhcp_check_profile_t *dhcp_check_profile_ptr_rx = NULL;
dhcp_check_profile_t *dhcp_check_profile_ptr_tx = NULL;
dhcpv6_check_profile_t *dhcpv6_check_profile_ptr_rx = NULL;
dhcpv6_check_profile_t *dhcpv6_check_profile_ptr_tx = NULL;

std::string generate_addr_string(const uint8_t *addr, size_t addr_len)
{
    std::string out;
    char b[4];
    for (size_t i = 0; i < addr_len; ++i) {
        snprintf(b, sizeof(b), "%02x", addr[i]);
        out += b;
    }
    return out;
}

uint16_t calculate_ip_checksum(const struct iphdr *) { return 0; }
uint16_t calculate_udp_checksum(const struct udphdr *, const uint8_t *, bool) { return 0; }

static sock_info_t g_stub_sock_info;
sock_info_t &sock_mgr_get_sock_info(int) { return g_stub_sock_info; }

bool intf_is_standby(const std::string &) { return false; }
const dhcp_device_context_t *dhcp_devman_get_device_context(const std::string &) { return NULL; }
std::string dhcp_devman_get_agg_counter_ifname(const std::string &ifname) { return agg_dev_prefix + ifname; }

/* The unit under test. */
#include "src/packet_handler.cpp"

/* ------------------------------------------------------------------ */

static int g_failures = 0;
static int g_checks = 0;

static void check(const char *group, const char *name, bool ok, const char *detail)
{
    g_checks++;
    if (!ok) {
        g_failures++;
    }
    printf("  [%s] %-10s %-46s %s\n", ok ? "PASS" : "FAIL", group, name, detail);
}

/** Allocate a buffer of exactly n bytes so ASan poisons the byte at index n. */
static uint8_t *exact_buf(const uint8_t *data, size_t n)
{
    uint8_t *p = (uint8_t *)calloc(n ? n : 1, 1);
    if (n) {
        memcpy(p, data, n);
    }
    return p;
}

/* ================================================================== *
 * DHCPv4: find_dhcp_option_53
 *
 * These cases correspond to the original F055 report, which described an
 * out-of-bounds read of the option length byte. That code path was rewritten
 * upstream and already carries the necessary guards; these tests pin that
 * behaviour so it cannot regress.
 * ================================================================== */
static void test_dhcpv4_option_53(void)
{
    printf("\nDHCPv4 find_dhcp_option_53 (pins the behaviour described by F055)\n");

    /* The exact payload from the F055 report: a one byte options area holding
     * an option code with no length byte following it. */
    {
        const uint8_t opts[] = { 0x01 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        const uint8_t *r = find_dhcp_option_53(b, (ssize_t)sizeof(opts));
        check("v4", "F055 PoC: tag with no length byte", r == NULL,
              "rejected without reading the absent length byte");
        free(b);
    }

    /* Option declaring a length that runs past the options area. */
    {
        const uint8_t opts[] = { 0x01, 0x10, 0xaa };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v4", "over-long option rejected",
              find_dhcp_option_53(b, (ssize_t)sizeof(opts)) == NULL,
              "declared value exceeds buffer");
        free(b);
    }

    /* Empty options area. */
    {
        uint8_t *b = exact_buf(NULL, 0);
        check("v4", "empty options area", find_dhcp_option_53(b, 0) == NULL,
              "no read performed");
        free(b);
    }

    /* Pad options followed by a truncated option. */
    {
        const uint8_t opts[] = { 0x00, 0x00, 0x35 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v4", "padding then truncated option",
              find_dhcp_option_53(b, (ssize_t)sizeof(opts)) == NULL,
              "padding skipped, truncation detected");
        free(b);
    }

    /* Option 53 present and well formed must still be found. */
    {
        const uint8_t opts[] = { 0x35, 0x01, 0x03 };   /* tag 53, len 1, DHCPREQUEST */
        uint8_t *b = exact_buf(opts, sizeof(opts));
        const uint8_t *r = find_dhcp_option_53(b, (ssize_t)sizeof(opts));
        check("v4", "well-formed option 53 found", r != NULL && r[0] == 0x03,
              "no functional regression");
        free(b);
    }

    /* Option 53 located after an unrelated option. */
    {
        const uint8_t opts[] = { 0x0c, 0x02, 0x61, 0x62, 0x35, 0x01, 0x05 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        const uint8_t *r = find_dhcp_option_53(b, (ssize_t)sizeof(opts));
        check("v4", "option 53 after another option", r != NULL && r[0] == 0x05,
              "walk advances correctly");
        free(b);
    }

    /* Terminator ends the walk. */
    {
        const uint8_t opts[] = { 0xff, 0x35, 0x01, 0x05 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v4", "end option terminates walk",
              find_dhcp_option_53(b, (ssize_t)sizeof(opts)) == NULL,
              "nothing parsed past 0xff");
        free(b);
    }

    /* Zero-length option 53 returns a pointer that callers must not read;
     * confirm the walker still reports it without touching the value. */
    {
        const uint8_t opts[] = { 0x35, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        const uint8_t *r = find_dhcp_option_53(b, (ssize_t)sizeof(opts));
        check("v4", "zero-length option 53 not dereferenced", r != NULL,
              "returned without reading the empty value");
        free(b);
    }
}

/* ================================================================== *
 * DHCPv6: find_dhcpv6_option
 * ================================================================== */
static void test_dhcpv6_find_option(void)
{
    printf("\nDHCPv6 find_dhcpv6_option\n");

    /* F055 class: relay-msg option declaring length 0 at the end of the area.
     * Before remediation the caller dereferenced the returned pointer, which
     * pointed one byte past the options area. */
    {
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        uint16_t len = 0xffff;
        const uint8_t *r = find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, b, (ssize_t)sizeof(opts), &len);
        check("v6-find", "zero-length option reports len 0", r != NULL && len == 0,
              "caller can tell there is no value to read");
        free(b);
    }

    /* Option declaring more bytes than remain. */
    {
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x40 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        uint16_t len = 0;
        check("v6-find", "over-long option rejected",
              find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, b, (ssize_t)sizeof(opts), &len) == NULL,
              "value would extend past the options area");
        free(b);
    }

    /* Header truncated to the code only. */
    {
        const uint8_t opts[] = { 0x00, 0x09 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        uint16_t len = 0;
        check("v6-find", "code without length rejected",
              find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, b, (ssize_t)sizeof(opts), &len) == NULL,
              "length bytes never read");
        free(b);
    }

    /* Empty options area. */
    {
        uint8_t *b = exact_buf(NULL, 0);
        uint16_t len = 0;
        check("v6-find", "empty options area",
              find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, b, 0, &len) == NULL,
              "no read performed");
        free(b);
    }

    /* Well-formed option is found and its value is reachable. */
    {
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        uint16_t len = 0;
        const uint8_t *r = find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, b, (ssize_t)sizeof(opts), &len);
        check("v6-find", "well-formed option found", r != NULL && len == 4 && r[0] == 0x01,
              "no functional regression");
        free(b);
    }

    /* Target option located after a preceding option. */
    {
        const uint8_t opts[] = { 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb,
                                 0x00, 0x12, 0x00, 0x01, 0x7f };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        uint16_t len = 0;
        const uint8_t *r = find_dhcpv6_option(OPTION_DHCPV6_INTERFACE_ID, b, (ssize_t)sizeof(opts), &len);
        check("v6-find", "option found after another option", r != NULL && len == 1 && r[0] == 0x7f,
              "walk advances correctly");
        free(b);
    }

    /* A truncated trailing option must not be reported even if an earlier
     * option parsed cleanly. */
    {
        const uint8_t opts[] = { 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb,
                                 0x00, 0x12, 0x00, 0x08, 0x01 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        uint16_t len = 0;
        check("v6-find", "truncated trailing option rejected",
              find_dhcpv6_option(OPTION_DHCPV6_INTERFACE_ID, b, (ssize_t)sizeof(opts), &len) == NULL,
              "declared length exceeds remaining bytes");
        free(b);
    }

    /* Absent option still reports absence. */
    {
        const uint8_t opts[] = { 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        uint16_t len = 0;
        check("v6-find", "absent option returns NULL",
              find_dhcpv6_option(OPTION_DHCPV6_RELAY_MSG, b, (ssize_t)sizeof(opts), &len) == NULL,
              "absence reported as absence");
        free(b);
    }
}

/* ================================================================== *
 * DHCPv6: dhcpv6_sanity_check
 * ================================================================== */
static void test_dhcpv6_sanity_check(void)
{
    printf("\nDHCPv6 dhcpv6_sanity_check\n");
    const std::string ifn = "Vlan1000";

    /* The F055-class payload: a relay message option declaring length 0 as the
     * final option. Upstream read the inner message type byte from one past the
     * end of the options area. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_RELAY_FORW };
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "F055 PoC: empty relay-msg rejected",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == false,
              "no read past the options area");
        free(b);
    }

    /* Relay message shorter than a bare DHCPv6 header. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_RELAY_FORW };
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x02, 0x01, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "undersized inner message rejected",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == false,
              "inner options size cannot go negative");
        free(b);
    }

    /* Inner message announces a relay type but is too short for a relay header. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_RELAY_FORW };
        uint8_t opts[4 + 8] = { 0x00, 0x09, 0x00, 0x08 };
        opts[4] = DHCPV6_MESSAGE_TYPE_RELAY_FORW;   /* needs 34 bytes, only 8 given */
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "inner relay shorter than relay header",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == false,
              "rejected instead of computing a negative size");
        free(b);
    }

    /* Option code beyond the IANA maximum. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_SOLICIT };
        const uint8_t opts[] = { 0x01, 0x00, 0x00, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "out-of-range option code rejected",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == false,
              "existing guard preserved");
        free(b);
    }

    /* Option header truncated to the code. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_SOLICIT };
        const uint8_t opts[] = { 0x00, 0x01, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "code without length rejected",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == false,
              "existing guard preserved");
        free(b);
    }

    /* Option value running past the options area. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_SOLICIT };
        const uint8_t opts[] = { 0x00, 0x01, 0x00, 0x20, 0xaa };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "over-long option rejected",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == false,
              "existing guard preserved");
        free(b);
    }

    /* Non-relay message carrying a well-formed option must be accepted. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_SOLICIT };
        const uint8_t opts[] = { 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "well-formed solicit accepted",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == true,
              "no functional regression");
        free(b);
    }

    /* Non-relay message must not carry a relay-msg option. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_SOLICIT };
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "solicit with relay-msg rejected",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == false,
              "existing relay/non-relay consistency guard preserved");
        free(b);
    }

    /* Relay message with a well-formed encapsulated Solicit must be accepted. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_RELAY_FORW };
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x04,
                                 DHCPV6_MESSAGE_TYPE_SOLICIT, 0x00, 0x00, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "relay with valid inner solicit accepted",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == true,
              "no functional regression");
        free(b);
    }

    /* Relay message missing its relay-msg option. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_RELAY_FORW };
        const uint8_t opts[] = { 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "relay without relay-msg rejected",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == false,
              "existing relay/non-relay consistency guard preserved");
        free(b);
    }

    /* Nested relay: outer relay carries an inner relay with its own inner
     * Solicit. Exercises the recursive path with exact sizing. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_RELAY_FORW };
        uint8_t opts[4 + 34 + 8];
        memset(opts, 0, sizeof(opts));
        opts[1] = 0x09;                                   /* relay-msg */
        opts[2] = 0x00;
        opts[3] = 34 + 8;                                 /* inner relay hdr + its relay-msg */
        opts[4] = DHCPV6_MESSAGE_TYPE_RELAY_FORW;         /* inner message is a relay */
        opts[4 + 34 + 1] = 0x09;                          /* inner relay-msg option */
        opts[4 + 34 + 3] = 0x04;
        opts[4 + 34 + 4] = DHCPV6_MESSAGE_TYPE_SOLICIT;
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-sanity", "nested relay accepted",
              dhcpv6_sanity_check(ifn, hdr, b, (ssize_t)sizeof(opts)) == true,
              "recursive path sized exactly, no overread");
        free(b);
    }

    /* Empty options area on a non-relay message. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_SOLICIT };
        uint8_t *b = exact_buf(NULL, 0);
        check("v6-sanity", "empty options area accepted",
              dhcpv6_sanity_check(ifn, hdr, b, 0) == true,
              "no read performed");
        free(b);
    }

    /* Negative options size must be tolerated without any read. */
    {
        const uint8_t hdr[] = { DHCPV6_MESSAGE_TYPE_SOLICIT };
        uint8_t *b = exact_buf(NULL, 0);
        check("v6-sanity", "negative options size tolerated",
              dhcpv6_sanity_check(ifn, hdr, b, -30) == true,
              "loop guard holds for negative sizes");
        free(b);
    }
}

/* ================================================================== *
 * DHCPv6: check_dhcpv6_message_type
 *
 * This is the second site that dereferenced the pointer returned by
 * find_dhcpv6_option without establishing that a value byte exists.
 * dhcpv6_sanity_check now rejects such packets earlier, so these cases pin
 * the defence-in-depth guard in the consumer itself.
 * ================================================================== */
static void test_dhcpv6_check_message_type(void)
{
    printf("\nDHCPv6 check_dhcpv6_message_type\n");

    dhcp_device_context_t context;
    memset(&context, 0, sizeof(context));
    snprintf(context.intf, sizeof(context.intf), "Vlan1000");
    context.intf_type = DHCP_DEVICE_INTF_TYPE_DOWNLINK;

    struct ip6_hdr ip6hdr;
    memset(&ip6hdr, 0, sizeof(ip6hdr));

    bool has_relay_opt = true;
    in6_addr link_addr;
    memset(&link_addr, 0, sizeof(link_addr));
    std::vector<const in6_addr *> link_addrs = { &link_addr };

    /* The pointer returned by find_dhcpv6_option is only dereferenced when the
     * profile asks for a link-address check conditioned on the inner message
     * type, which falls through into the relay-option case. A profile with
     * only DHCPV6_CHECK_HAS_RELAY_OPT set breaks out before the dereference. */
    dhcpv6_msg_check_profile_t profile;
    profile[DHCPV6_CHECK_HAS_RELAY_OPT] = &has_relay_opt;
    profile[DHCPV6_CHECK_LINK_ADDR_INNER_MSG_RELAY] = &link_addrs;

    const uint8_t dhcp6hdr[DHCPV6_RELAY_HEADER_SIZE] = { DHCPV6_MESSAGE_TYPE_RELAY_FORW };

    /* Relay message option present but empty: the inner message type byte
     * sits one past the options area and must not be read. */
    {
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-msgtype", "empty relay-msg not dereferenced",
              check_dhcpv6_message_type(&profile, &context, &ip6hdr, dhcp6hdr, b, (ssize_t)sizeof(opts)) == false,
              "rejected without reading the absent value");
        free(b);
    }

    /* Relay message option carrying an inner message type is accepted. The
     * inner message is a Solicit, so the link-address check is skipped. */
    {
        const uint8_t opts[] = { 0x00, 0x09, 0x00, 0x04,
                                 DHCPV6_MESSAGE_TYPE_SOLICIT, 0x00, 0x00, 0x00 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-msgtype", "well-formed relay-msg accepted",
              check_dhcpv6_message_type(&profile, &context, &ip6hdr, dhcp6hdr, b, (ssize_t)sizeof(opts)) == true,
              "no functional regression");
        free(b);
    }

    /* Profile expects the relay option but the packet has none. */
    {
        const uint8_t opts[] = { 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-msgtype", "missing relay-msg rejected",
              check_dhcpv6_message_type(&profile, &context, &ip6hdr, dhcp6hdr, b, (ssize_t)sizeof(opts)) == false,
              "presence expectation still enforced");
        free(b);
    }

    /* Interface-id option of the wrong length must be rejected, and the
     * 16 byte comparison must never run against a short option. */
    {
        in6_addr expected;
        memset(&expected, 0, sizeof(expected));
        std::vector<const in6_addr *> ips = { &expected };
        dhcpv6_msg_check_profile_t id_profile;
        id_profile[DHCPV6_CHECK_INTERFACE_ID] = &ips;

        const uint8_t opts[] = { 0x00, 0x12, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-msgtype", "short interface-id rejected",
              check_dhcpv6_message_type(&id_profile, &context, &ip6hdr, dhcp6hdr, b, (ssize_t)sizeof(opts)) == false,
              "no 16 byte read against a 4 byte option");
        free(b);
    }

    /* A truncated interface-id option must not be reported as present. */
    {
        in6_addr expected;
        memset(&expected, 0, sizeof(expected));
        std::vector<const in6_addr *> ips = { &expected };
        dhcpv6_msg_check_profile_t id_profile;
        id_profile[DHCPV6_CHECK_INTERFACE_ID] = &ips;

        const uint8_t opts[] = { 0x00, 0x12, 0x00, 0x10, 0x01, 0x02 };
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-msgtype", "truncated interface-id treated as absent",
              check_dhcpv6_message_type(&id_profile, &context, &ip6hdr, dhcp6hdr, b, (ssize_t)sizeof(opts)) == true,
              "optional option, no read past the options area");
        free(b);
    }

    /* A correctly sized interface-id matching the expected value is accepted. */
    {
        in6_addr expected;
        memset(&expected, 0xab, sizeof(expected));
        std::vector<const in6_addr *> ips = { &expected };
        dhcpv6_msg_check_profile_t id_profile;
        id_profile[DHCPV6_CHECK_INTERFACE_ID] = &ips;

        uint8_t opts[4 + 16];
        memset(opts, 0xab, sizeof(opts));
        opts[0] = 0x00; opts[1] = 0x12; opts[2] = 0x00; opts[3] = 0x10;
        uint8_t *b = exact_buf(opts, sizeof(opts));
        check("v6-msgtype", "matching interface-id accepted",
              check_dhcpv6_message_type(&id_profile, &context, &ip6hdr, dhcp6hdr, b, (ssize_t)sizeof(opts)) == true,
              "no functional regression");
        free(b);
    }
}

/* ================================================================== *
 * End to end: packet_handler_v6
 *
 * Drives complete Ethernet/IPv6/UDP/DHCPv6 frames through the real entry
 * point. This covers the options-size computation, which the remediation
 * restructured, and proves that well-formed traffic is still counted under
 * the correct message type.
 * ================================================================== */

/** Build a frame and return its total length. dhcp6_payload is placed directly
 *  after the UDP header. */
static size_t build_v6_frame(std::vector<uint8_t> &frame,
                             const uint8_t *dhcp6_payload, size_t dhcp6_payload_sz,
                             uint16_t udp_len_override)
{
    const size_t udp_off = IP_START_OFFSET + sizeof(struct ip6_hdr);
    const size_t dhcp6_off = udp_off + sizeof(struct udphdr);
    const size_t total = dhcp6_off + dhcp6_payload_sz;

    frame.assign(total, 0);

    struct ip6_hdr *ip6hdr = (struct ip6_hdr *)(frame.data() + IP_START_OFFSET);
    ip6hdr->ip6_nxt = IPPROTO_UDP;
    ip6hdr->ip6_plen = htons((uint16_t)(sizeof(struct udphdr) + dhcp6_payload_sz));

    struct udphdr *udphdr = (struct udphdr *)(frame.data() + udp_off);
    udphdr->source = htons(547);
    udphdr->dest = htons(547);
    udphdr->len = htons(udp_len_override ? udp_len_override
                                         : (uint16_t)(sizeof(struct udphdr) + dhcp6_payload_sz));
    udphdr->check = 0;

    if (dhcp6_payload_sz) {
        memcpy(frame.data() + dhcp6_off, dhcp6_payload, dhcp6_payload_sz);
    }
    return total;
}

static uint64_t counter_for(const std::string &ifname, uint8_t type)
{
    auto &counters = g_stub_sock_info.all_counters;
    auto it = counters.find(ifname);
    if (it == counters.end()) {
        return 0;
    }
    auto c = it->second.find(type);
    return c == it->second.end() ? 0 : c->second;
}

static void test_packet_handler_v6_end_to_end(void)
{
    printf("\nEnd to end packet_handler_v6\n");

    const std::string ifn = "Vlan1000";

    dhcp_device_context_t context;
    memset(&context, 0, sizeof(context));
    snprintf(context.intf, sizeof(context.intf), "Vlan1000");
    context.intf_type = DHCP_DEVICE_INTF_TYPE_DOWNLINK;

    /* tx socket: checksum validation is skipped for transmitted packets */
    g_stub_sock_info.sock = 1;
    g_stub_sock_info.name = "tx_v6";
    g_stub_sock_info.is_rx = false;
    g_stub_sock_info.is_v6 = true;
    g_stub_sock_info.all_counters[ifn] = counter_t();
    g_stub_sock_info.all_counters[agg_dev_prefix + ifn] = counter_t();

    /* An empty per-message profile leaves every check entry NULL, so all
     * checks are skipped and a well-formed message is accepted. That isolates
     * these cases to the parsing behaviour under test. */
    static dhcpv6_msg_check_profile_t empty_msg_profile;
    static dhcpv6_check_profile_t tx_profile;
    tx_profile[DHCPV6_MESSAGE_TYPE_SOLICIT] = &empty_msg_profile;
    tx_profile[DHCPV6_MESSAGE_TYPE_RELAY_FORW] = &empty_msg_profile;
    dhcpv6_check_profile_ptr_tx = &tx_profile;
    dhcpv6_check_profile_ptr_rx = &tx_profile;

    /* A relay-forward frame whose UDP length only covers a bare DHCPv6 header.
     * The relay header is 34 bytes, so the options size would be negative. */
    {
        uint8_t payload[4] = { DHCPV6_MESSAGE_TYPE_RELAY_FORW, 0, 0, 0 };
        std::vector<uint8_t> frame;
        size_t sz = build_v6_frame(frame, payload, sizeof(payload), 0);
        g_stub_sock_info.buffer = frame.data();

        uint64_t before = counter_for(ifn, DHCPV6_MESSAGE_TYPE_MALFORMED);
        packet_handler_v6(1, ifn, &context, (ssize_t)sz);
        check("v6-e2e", "relay frame too short for relay header",
              counter_for(ifn, DHCPV6_MESSAGE_TYPE_MALFORMED) == before + 1,
              "counted malformed, no pointer past the capture buffer");
    }

    /* The F055 payload delivered as a real frame: relay-forward carrying a
     * relay-msg option that declares length 0. */
    {
        uint8_t payload[DHCPV6_RELAY_HEADER_SIZE + 4];
        memset(payload, 0, sizeof(payload));
        payload[0] = DHCPV6_MESSAGE_TYPE_RELAY_FORW;
        payload[DHCPV6_RELAY_HEADER_SIZE + 1] = 0x09;   /* relay-msg, length 0 */
        std::vector<uint8_t> frame;
        size_t sz = build_v6_frame(frame, payload, sizeof(payload), 0);
        g_stub_sock_info.buffer = frame.data();

        uint64_t before = counter_for(ifn, DHCPV6_MESSAGE_TYPE_MALFORMED);
        packet_handler_v6(1, ifn, &context, (ssize_t)sz);
        check("v6-e2e", "F055 PoC frame counted malformed",
              counter_for(ifn, DHCPV6_MESSAGE_TYPE_MALFORMED) == before + 1,
              "rejected without reading past the options area");
    }

    /* A well-formed Solicit must still be counted as a Solicit. */
    {
        uint8_t payload[DHCPV6_HEADER_SIZE + 6];
        memset(payload, 0, sizeof(payload));
        payload[0] = DHCPV6_MESSAGE_TYPE_SOLICIT;
        payload[DHCPV6_HEADER_SIZE + 1] = 0x01;         /* client id option */
        payload[DHCPV6_HEADER_SIZE + 3] = 0x02;         /* length 2 */
        std::vector<uint8_t> frame;
        size_t sz = build_v6_frame(frame, payload, sizeof(payload), 0);
        g_stub_sock_info.buffer = frame.data();

        uint64_t before = counter_for(ifn, DHCPV6_MESSAGE_TYPE_SOLICIT);
        packet_handler_v6(1, ifn, &context, (ssize_t)sz);
        check("v6-e2e", "well-formed solicit still counted",
              counter_for(ifn, DHCPV6_MESSAGE_TYPE_SOLICIT) == before + 1,
              "no functional regression");
    }

    /* A well-formed relay-forward carrying an encapsulated Solicit. */
    {
        uint8_t payload[DHCPV6_RELAY_HEADER_SIZE + 4 + 4];
        memset(payload, 0, sizeof(payload));
        payload[0] = DHCPV6_MESSAGE_TYPE_RELAY_FORW;
        payload[DHCPV6_RELAY_HEADER_SIZE + 1] = 0x09;   /* relay-msg */
        payload[DHCPV6_RELAY_HEADER_SIZE + 3] = 0x04;   /* length 4 */
        payload[DHCPV6_RELAY_HEADER_SIZE + 4] = DHCPV6_MESSAGE_TYPE_SOLICIT;
        std::vector<uint8_t> frame;
        size_t sz = build_v6_frame(frame, payload, sizeof(payload), 0);
        g_stub_sock_info.buffer = frame.data();

        uint64_t before = counter_for(ifn, DHCPV6_MESSAGE_TYPE_RELAY_FORW);
        packet_handler_v6(1, ifn, &context, (ssize_t)sz);
        check("v6-e2e", "well-formed relay-forward still counted",
              counter_for(ifn, DHCPV6_MESSAGE_TYPE_RELAY_FORW) == before + 1,
              "no functional regression");
    }

    g_stub_sock_info.buffer = NULL;
}

/* ================================================================== */
int main(void)
{
    printf("dhcpmon option parser unit tests (F055 / ADO 39703091)\n");
    printf("=======================================================\n");

    test_dhcpv4_option_53();
    test_dhcpv6_find_option();
    test_dhcpv6_sanity_check();
    test_dhcpv6_check_message_type();
    test_packet_handler_v6_end_to_end();

    printf("\n=======================================================\n");
    printf("%d checks, %d failure%s\n", g_checks, g_failures, g_failures == 1 ? "" : "s");
    printf("%s\n", g_failures == 0 ? "RESULT: PASS" : "RESULT: FAIL");
    return g_failures == 0 ? 0 : 1;
}
