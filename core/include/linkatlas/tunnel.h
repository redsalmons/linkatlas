/*
 * Full-traffic tunnel: takes raw IP packets from the platform VPN interface,
 * terminates TCP/UDP locally with lwIP and forwards the payload unchanged to
 * the original destination over normal sockets. Bounded App packet samples are
 * observed before lwIP; byte streams and UDP datagrams are observed separately.
 *
 * One tunnel per process (lwIP keeps global state).
 */
#ifndef LINKATLAS_TUNNEL_H
#define LINKATLAS_TUNNEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wd_tunnel wd_tunnel;

typedef enum {
    WD_DIR_OUTBOUND = 0, /* device -> network (read from the VPN interface) */
    WD_DIR_INBOUND = 1   /* server -> app */
} wd_direction;

#define WD_PROTO_TCP 6
#define WD_PROTO_UDP 17

/* Identifies a flow from the app's point of view: src is the app side of the
   tunnel, dst is the original destination. Addresses are network-order bytes;
   IPv4 uses only the first 4 bytes. */
typedef struct {
    uint8_t src[16], dst[16];
    uint16_t sport, dport;
    uint8_t ipver; /* 4 or 6 */
    uint8_t proto; /* WD_PROTO_* */
} wd_flow_key;

typedef enum {
    WD_FLOW_OPEN, WD_PACKET, WD_TCP_DATA, WD_STREAM_END, WD_UDP_DATAGRAM, WD_FLOW_CLOSE,
    WD_FLOW_STATS
} wd_event_type;

typedef enum {
    WD_SOURCE_APP_PACKET, WD_SOURCE_APP_STREAM, WD_SOURCE_SERVER_STREAM,
    WD_SOURCE_APP_DATAGRAM, WD_SOURCE_SERVER_DATAGRAM, WD_SOURCE_LIFECYCLE
} wd_source;

enum {
    WD_FLAG_TRUNCATED = 1u,
    WD_FLAG_BUDGET = 2u,
    WD_FLAG_UNASSOCIATED = 4u,
    WD_FLAG_GAP = 8u,
    WD_FLAG_EXPIRED = 16u,
    WD_FLAG_CAPACITY = 32u
};

typedef enum {
    WD_CLOSE_NORMAL, WD_CLOSE_ERROR, WD_CLOSE_IDLE, WD_CLOSE_STOP, WD_CLOSE_REPLACED
} wd_close_reason;

/* All counters describe observation, not successful delivery to the peer.
   Ports are host order. flow_id is unique within a tunnel; 0 means unassociated.
   offset is a TCP byte offset or a UDP observation ordinal, per direction.
   flags[direction] are cumulative capture limitations. */
typedef struct {
    wd_event_type type;
    wd_source source;
    wd_direction direction;
    wd_close_reason close_reason;
    wd_flow_key flow;
    uint64_t flow_id, timestamp_ms, offset;
    uint64_t bytes[2], datagrams[2], app_packets, app_packet_bytes;
    uint64_t offered[2]; /* TCP sample bytes / UDP samples attempted, even if queue drops */
    uint32_t flags[2];
    const uint8_t *data;
    size_t length;       /* length before capture truncation */
    size_t captured;     /* bytes accessible at data */
} wd_event;

#define WD_CAPTURE_CHUNK 4096
#define WD_CAPTURE_STREAM_BYTES 32768

/* Write one IP packet to the VPN interface. Called on the tunnel thread. */
typedef void (*wd_output_fn)(void *ctx, const uint8_t *packet, size_t len);
/* Exclude an outgoing socket from the VPN (Android VpnService.protect). Return 0 on success. */
typedef int (*wd_protect_fn)(void *ctx, int fd);
/* Observation only: no verdict and no ownership transfer. Copy data before
   returning. Called serially by the tunnel thread (destroy may emit final
   events on its caller after joining that thread). Must not block. */
typedef void (*wd_observer_fn)(void *ctx, const wd_event *event);

wd_tunnel *wd_tunnel_create(wd_output_fn output, wd_protect_fn protect, void *ctx,
                            wd_observer_fn observer, void *observer_ctx);
/* Thread-safe. Queues one IP packet read from the VPN interface. */
void wd_tunnel_input(wd_tunnel *t, const uint8_t *packet, size_t len);
void wd_tunnel_destroy(wd_tunnel *t);

/* Fill buf with the underlying network's DNS servers as a comma-separated
   list. Returns the number of servers written; 0 when unavailable. */
int wd_dns_servers(char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
