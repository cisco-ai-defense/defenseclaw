/* Local SSRF guard for every edge profile. Network names cannot be checked
 * safely here: a later agent connection can resolve to a different address.
 * Until egress is pinned by a proxy, accept only explicit public IP literals. */
#include "content_scanner.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>

void dclaw_ssrf_init_tables(void) {
    /* Address parsing needs no runtime tables. */
}

static bool public_ipv4(const struct in_addr *addr) {
    const uint8_t *ip = (const uint8_t *)&addr->s_addr;
    if (ip[0] == 0 || ip[0] == 10 || ip[0] == 127 || ip[0] >= 224) return false;
    if (ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) return false;
    if (ip[0] == 169 && ip[1] == 254) return false;
    if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) return false;
    if (ip[0] == 192 && ip[1] == 168) return false;
    if (ip[0] == 192 && ip[1] == 0 && (ip[2] == 0 || ip[2] == 2)) return false;
    if (ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)) return false;
    if (ip[0] == 198 && ip[1] == 51 && ip[2] == 100) return false;
    if (ip[0] == 203 && ip[1] == 0 && ip[2] == 113) return false;
    return true;
}

static bool public_ipv6(const struct in6_addr *addr) {
    /* Only global unicast 2000::/3. This excludes loopback, ULA, link-local,
     * multicast and IPv4-mapped addresses (including ::ffff:127.0.0.1). */
    if ((addr->s6_addr[0] & 0xe0) != 0x20) return false;
    /* IANA documentation/transition ranges are not public egress targets. */
    if (addr->s6_addr[0] == 0x20 && addr->s6_addr[1] == 0x01 &&
        addr->s6_addr[2] == 0x0d && addr->s6_addr[3] == 0xb8) return false;
    if (addr->s6_addr[0] == 0x20 && addr->s6_addr[1] == 0x02) return false;
    return true;
}

static bool valid_port(const char *start, const char *end) {
    if (start == end) return false;
    unsigned port = 0;
    for (const char *p = start; p < end; p++) {
        if (!isdigit((unsigned char)*p)) return false;
        port = port * 10 + (unsigned)(*p - '0');
        if (port > 65535) return false;
    }
    return port != 0;
}

dclaw_action_t dclaw_ssrf_check_destination(const char *dest) {
    if (!dest || !*dest) return DCLAW_ACTION_ALLOW; /* non-network tool */

    const char *authority = dest;
    if (strncmp(dest, "https://", 8) == 0) authority += 8;
    else if (strncmp(dest, "http://", 7) == 0) authority += 7;
    else if (strstr(dest, "://")) return DCLAW_ACTION_BLOCK;

    const char *end = authority;
    while (*end && *end != '/' && *end != '?' && *end != '#') {
        unsigned char c = (unsigned char)*end;
        if (c <= 0x20 || c >= 0x7f || c == '@' || c == '\\' || c == '%')
            return DCLAW_ACTION_BLOCK;
        end++;
    }
    if (authority == end) return DCLAW_ACTION_BLOCK;

    char host[256];
    const char *host_end;
    bool ipv6 = *authority == '[';
    if (ipv6) {
        host_end = memchr(authority + 1, ']', (size_t)(end - authority - 1));
        if (!host_end || host_end == authority + 1) return DCLAW_ACTION_BLOCK;
        size_t len = (size_t)(host_end - authority - 1);
        if (len >= sizeof(host)) return DCLAW_ACTION_BLOCK;
        memcpy(host, authority + 1, len);
        host[len] = '\0';
        host_end++;
    } else {
        host_end = memchr(authority, ':', (size_t)(end - authority));
        if (!host_end) host_end = end;
        size_t len = (size_t)(host_end - authority);
        if (len == 0 || len >= sizeof(host)) return DCLAW_ACTION_BLOCK;
        memcpy(host, authority, len);
        host[len] = '\0';
    }
    if (host_end != end && (*host_end != ':' || !valid_port(host_end + 1, end)))
        return DCLAW_ACTION_BLOCK;

    if (ipv6) {
        struct in6_addr addr;
        if (inet_pton(AF_INET6, host, &addr) != 1 || !public_ipv6(&addr))
            return DCLAW_ACTION_BLOCK;
    } else {
        struct in_addr addr;
        /* inet_pton rejects hostnames, decimal-integer, hex, and octal aliases.
         * Their later resolver behavior can differ from our local parse. */
        if (inet_pton(AF_INET, host, &addr) != 1 || !public_ipv4(&addr))
            return DCLAW_ACTION_BLOCK;
    }
    return DCLAW_ACTION_ALLOW;
}
