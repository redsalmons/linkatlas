#ifndef LINKATLAS_CAPTURE_H
#define LINKATLAS_CAPTURE_H

#include "linkatlas/tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WD_CAPTURE_FLOWS 256

typedef struct {
    wd_event event;
    uint64_t created, first_data, last_active, last_report;
    uint32_t syn_sequence;
    unsigned bound : 1;
    unsigned has_syn : 1;
} wd_capture_flow;

typedef struct {
    wd_observer_fn observer;
    void *ctx;
    uint64_t next_id;
    wd_capture_flow flows[WD_CAPTURE_FLOWS];
} wd_capture;

/* Producer-only, allocation-free capture; stable entries until close. */
void wd_capture_packet(wd_capture *capture, const uint8_t *data, size_t len, uint64_t now);
wd_capture_flow *wd_capture_bind(wd_capture *capture, const wd_flow_key *key, uint64_t now);
void wd_capture_data(wd_capture *capture, wd_capture_flow *flow, wd_direction direction,
                     const uint8_t *data, size_t len, uint64_t now);
void wd_capture_end(wd_capture *capture, wd_capture_flow *flow, wd_direction direction,
                    uint64_t now);
void wd_capture_close(wd_capture *capture, wd_capture_flow *flow, wd_close_reason reason,
                      uint64_t now);
void wd_capture_expire(wd_capture *capture, uint64_t now);

/* Parses only complete, unfragmented TCP/UDP IP packets. No payload reassembly.
   Used for flow association and by the analyzer for bounded packet samples.
   With allow_prefix, the declared packet may exceed len, but headers may not. */
int wd_packet_key(const uint8_t *data, size_t len, int allow_prefix,
                  wd_flow_key *key, size_t *transport);

#ifdef __cplusplus
}
#endif
#endif
