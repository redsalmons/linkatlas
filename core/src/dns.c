/* Platform DNS discovery for tunnel configuration.
 *
 * A default-route VPN must also supply DNS resolvers, but hardcoding public
 * resolvers breaks on networks that cannot reach them. On Apple platforms the
 * per-interface resolver state exposes the underlying network's own servers;
 * elsewhere there is no equivalent API and the caller falls back to its
 * built-in list.
 */
#include "linkatlas/tunnel.h"

#if defined(__APPLE__)
#include <arpa/inet.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>

int wd_dns_servers(char *buf, size_t len) {
    if (!buf || !len) return 0;
    buf[0] = '\0';
    struct __res_state storage;
    memset(&storage, 0, sizeof(storage));
    res_state state = &storage;
    if (res_ninit(state) != 0) return 0;
    int nservers = state->nscount;
    if (nservers > MAXNS) nservers = MAXNS;
    if (nservers < 0) nservers = 0;
    size_t off = 0;
    int count = 0;
    for (int i = 0; i < nservers; i++) {
        char ip[INET_ADDRSTRLEN];
        ip[0] = '\0';
        inet_ntop(AF_INET, &state->nsaddr_list[i].sin_addr, ip, sizeof(ip));
        if (!ip[0]) continue;
        int n = snprintf(buf + off, len - off, "%s%s", count ? "," : "", ip);
        if (n < 0 || (size_t)n >= len - off) break;
        off += (size_t)n;
        count++;
    }
    res_ndestroy(state);
    return count;
}

#else

int wd_dns_servers(char *buf, size_t len) {
    (void)buf; (void)len;
    return 0;
}

#endif
