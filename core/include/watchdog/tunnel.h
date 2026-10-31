/*
 * Full-traffic tunnel: takes raw IP packets from the platform VPN interface,
 * terminates TCP/UDP locally with lwIP and forwards the payload unchanged to
 * the original destination over normal sockets. Every captured packet is also
 * handed to a hook (the C++ analyzer) before it is processed.
 *
 * One tunnel per process (lwIP keeps global state).
 */
#ifndef WATCHDOG_TUNNEL_H
#define WATCHDOG_TUNNEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wd_tunnel wd_tunnel;

typedef enum {
    WD_DIR_OUTBOUND = 0, /* device -> network (read from the VPN interface) */
    WD_DIR_INBOUND = 1   /* network -> device (written to the VPN interface) */
} wd_direction;

/* Write one IP packet to the VPN interface. Called on the tunnel thread. */
typedef void (*wd_output_fn)(void *ctx, const uint8_t *packet, size_t len);
/* Exclude an outgoing socket from the VPN (Android VpnService.protect). Return 0 on success. */
typedef int (*wd_protect_fn)(void *ctx, int fd);
/* Receives every captured packet. Called on the tunnel thread; must return quickly. */
typedef void (*wd_packet_fn)(void *ctx, const uint8_t *packet, size_t len, wd_direction dir);

wd_tunnel *wd_tunnel_create(wd_output_fn output, wd_protect_fn protect, void *ctx,
                            wd_packet_fn hook, void *hook_ctx);
/* Thread-safe. Queues one IP packet read from the VPN interface. */
void wd_tunnel_input(wd_tunnel *t, const uint8_t *packet, size_t len);
void wd_tunnel_destroy(wd_tunnel *t);

#ifdef __cplusplus
}
#endif

#endif
