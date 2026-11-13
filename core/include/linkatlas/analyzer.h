/* C entry points of the C++ packet analyzer, usable from Swift, JNI and C. */
#ifndef LINKATLAS_ANALYZER_H
#define LINKATLAS_ANALYZER_H

#include "linkatlas/tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

void *wd_analyzer_create(void);
/* Stop/destroy the tunnel first. Drains queued observations before returning. */
void wd_analyzer_destroy(void *analyzer);
/* Single producer, allocation-free, never waits for the analysis worker. */
void wd_analyzer_on_event(void *analyzer, const wd_event *event);

typedef enum {
    WD_PROTOCOL_UNKNOWN, WD_PROTOCOL_HTTP, WD_PROTOCOL_TLS, WD_PROTOCOL_DNS,
    WD_PROTOCOL_QUIC /* TLS inside QUIC Initial; distinct from TLS over TCP */
} wd_protocol;

typedef struct {
    uint64_t flow_id;
    wd_flow_key flow;
    uint64_t first_seen_ms, last_seen_ms;
    uint64_t bytes[2], datagrams[2], app_packets, app_packet_bytes, packet_samples;
    uint32_t sources; /* bitset: 1u << wd_source */
    uint32_t flags[2]; /* cumulative stream/datagram capture/analysis limitations */
    uint32_t packet_flags; /* independent of stream completeness */
    wd_protocol protocol[2];
    wd_close_reason close_reason;
    uint8_t closed, analysis_expired;
    uint8_t app_hop_limit, app_tcp_syn_seen, app_tcp_options_len;
    uint16_t app_tcp_window;
    uint8_t app_tcp_options[40]; /* wire order; App-side SYN only */
    char http_host[256];
    char tls_sni[256];
    char dns_question[256]; /* most recent successfully parsed question */
} wd_flow_summary;

typedef struct {
    uint64_t enqueued, processed, dropped_data, dropped_control;
    uint64_t unassociated_packets, evicted_flows, expired_flows, parser_failures;
} wd_analyzer_stats;

/* Thread-safe copies. At most capacity recent retained flow summaries; not
   persistent history. No payload pointers escape. Do not race with destroy. */
size_t wd_analyzer_snapshot(void *analyzer, wd_flow_summary *out, size_t capacity);
/* Discards all retained summaries, destination totals and passive-DNS entries.
   The tunnel keeps running; only the reporting state is cleared. */
void wd_analyzer_reset(void *analyzer);
void wd_analyzer_get_stats(void *analyzer, wd_analyzer_stats *out);

/* Session totals, independent of the bounded recent-flow snapshot.
   A connection means an observed FLOW_OPEN, not a successful TCP handshake.
   Domain is observed TLS SNI / HTTP Host; DNS questions are not destination names. */
typedef struct {
    uint8_t ipver, dst[16];
    char domain[256];
    uint64_t tcp_connections, udp_flows;
    uint64_t bytes[2]; /* cumulative per-direction app-side bytes */
    uint8_t protocol; /* wd_protocol of the latest observing flow */
    uint8_t domain_source; /* 0 none, 1 TLS SNI, 2 HTTP Host, 3 passive-DNS guess */
    uint8_t has_fingerprint;
    uint8_t app_hop_limit;
    uint16_t app_tcp_window;
    uint8_t app_tcp_options[40];
    uint8_t app_tcp_options_len;
} wd_destination_summary;

/* Returns total required capacity, copying min(total, capacity) entries.
   Call with NULL/0 to size the buffer; retry if the returned size grows. */
size_t wd_analyzer_destinations(void *analyzer, wd_destination_summary *out, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
