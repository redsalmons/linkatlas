#include "capture.h"

#include <string.h>

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

int wd_packet_key(const uint8_t *p, size_t len, int prefix,
                  wd_flow_key *key, size_t *transport) {
    if (!p || len < 20) return 0;
    memset(key, 0, sizeof(*key));
    key->ipver = p[0] >> 4;
    size_t off, total;
    uint8_t proto;
    if (key->ipver == 4) {
        off = (p[0] & 15u) * 4u;
        total = be16(p + 2);
        if (off < 20 || off > len || total < off || (be16(p + 6) & 0x3fff)) return 0;
        memcpy(key->src, p + 12, 4);
        memcpy(key->dst, p + 16, 4);
        proto = p[9];
    } else if (key->ipver == 6) {
        if (len < 40 || be16(p + 4) == 0) return 0; /* no jumbograms */
        total = 40u + be16(p + 4);
        off = 40;
        memcpy(key->src, p + 8, 16);
        memcpy(key->dst, p + 24, 16);
        proto = p[6];
        for (unsigned n = 0; proto == 0 || proto == 43 || proto == 60 || proto == 51; ++n) {
            if (n == 8 || off + 2 > len || off + 2 > total) return 0;
            size_t step = proto == 51 ? (p[off + 1] + 2u) * 4u : (p[off + 1] + 1u) * 8u;
            proto = p[off];
            if (step < 8 || off + step > len || off + step > total) return 0;
            off += step;
        }
        /* Fragment headers (including atomic fragments) remain unassociated. */
    } else {
        return 0;
    }
    if (!prefix && total > len) return 0;
    size_t header = proto == WD_PROTO_TCP ? 20 : proto == WD_PROTO_UDP ? 8 : 0;
    if (!header || off + header > len || off + header > total) return 0;
    if (proto == WD_PROTO_TCP) {
        header = (p[off + 12] >> 4) * 4u;
        if (header < 20 || off + header > len || off + header > total) return 0;
    } else {
        size_t udp_len = be16(p + off + 4);
        if (udp_len < 8 || off + udp_len > total) return 0;
    }
    key->proto = proto;
    key->sport = be16(p + off);
    key->dport = be16(p + off + 2);
    *transport = off;
    return 1;
}

static int same_key(const wd_flow_key *a, const wd_flow_key *b) {
    return a->ipver == b->ipver && a->proto == b->proto &&
           a->sport == b->sport && a->dport == b->dport &&
           !memcmp(a->src, b->src, 16) && !memcmp(a->dst, b->dst, 16);
}

static wd_capture_flow *find_flow(wd_capture *c, const wd_flow_key *key) {
    wd_capture_flow *found = NULL;
    for (size_t i = 0; i < WD_CAPTURE_FLOWS; ++i) {
        wd_capture_flow *f = &c->flows[i];
        if (f->event.flow_id && same_key(&f->event.flow, key) &&
            (!found || f->event.flow_id > found->event.flow_id)) found = f;
    }
    return found;
}

static void emit(wd_capture *c, wd_capture_flow *f, wd_event_type type,
                 wd_source source, wd_direction dir, uint64_t now,
                 uint64_t offset, const uint8_t *data, size_t len, size_t captured) {
    wd_event e = f->event;
    e.type = type;
    e.source = source;
    e.direction = dir;
    e.timestamp_ms = now;
    e.offset = offset;
    e.data = data;
    e.length = len;
    e.captured = captured;
    c->observer(c->ctx, &e);
}

static wd_capture_flow *new_flow(wd_capture *c, const wd_flow_key *key, uint64_t now) {
    for (size_t i = 0; i < WD_CAPTURE_FLOWS; ++i) {
        wd_capture_flow *f = &c->flows[i];
        if (f->event.flow_id) continue;
        memset(f, 0, sizeof(*f));
        f->event.flow = *key;
        f->event.flow_id = ++c->next_id;
        f->created = f->last_active = f->last_report = now;
        emit(c, f, WD_FLOW_OPEN, WD_SOURCE_LIFECYCLE, WD_DIR_OUTBOUND, now, 0, NULL, 0, 0);
        return f;
    }
    return NULL; /* Analysis capacity never limits forwarding. */
}

void wd_capture_close(wd_capture *c, wd_capture_flow *f, wd_close_reason reason, uint64_t now) {
    if (!f) return;
    f->event.close_reason = reason;
    emit(c, f, WD_FLOW_CLOSE, WD_SOURCE_LIFECYCLE, WD_DIR_OUTBOUND, now, 0, NULL, 0, 0);
    memset(f, 0, sizeof(*f));
}

void wd_capture_packet(wd_capture *c, const uint8_t *data, size_t len, uint64_t now) {
    if (!c->observer) return;
    wd_flow_key key;
    size_t off;
    wd_capture_flow *f = NULL;
    if (wd_packet_key(data, len, 0, &key, &off)) {
        f = find_flow(c, &key);
        int syn = key.proto == WD_PROTO_TCP && (data[off + 13] & 0x12) == 0x02;
        uint32_t seq = syn ? ((uint32_t)be16(data + off + 4) << 16) | be16(data + off + 6) : 0;
        if (syn && f && f->has_syn && f->syn_sequence != seq) {
            /* A bound old connection keeps its record until its own close. */
            if (!f->bound) wd_capture_close(c, f, WD_CLOSE_REPLACED, now);
            f = NULL;
        }
        if (!f) f = new_flow(c, &key, now);
        if (f && syn) {
            f->has_syn = 1;
            f->syn_sequence = seq;
        }
    }
    if (!f) {
        wd_capture_flow unknown = {0};
        unknown.event.flags[0] = WD_FLAG_UNASSOCIATED;
        emit(c, &unknown, WD_PACKET, WD_SOURCE_APP_PACKET, WD_DIR_OUTBOUND,
             now, 0, data, len, len < 192 ? len : 192);
        return;
    }
    f->last_active = now;
    f->event.app_packets++;
    f->event.app_packet_bytes += len;
    if (f->event.app_packets <= 32) {
        emit(c, f, WD_PACKET, WD_SOURCE_APP_PACKET, WD_DIR_OUTBOUND,
             now, f->event.app_packets - 1, data, len, len < 192 ? len : 192);
    }
}

wd_capture_flow *wd_capture_bind(wd_capture *c, const wd_flow_key *key, uint64_t now) {
    if (!c->observer) return NULL;
    wd_capture_flow *f = find_flow(c, key);
    if (!f || f->bound) f = new_flow(c, key, now);
    if (f) f->bound = 1;
    return f;
}

void wd_capture_data(wd_capture *c, wd_capture_flow *f, wd_direction dir,
                     const uint8_t *data, size_t len, uint64_t now) {
    if (!f) return;
    f->last_active = now;
    uint64_t offset = f->event.bytes[dir];
    f->event.bytes[dir] += len;
    if (f->event.flow.proto == WD_PROTO_UDP) {
        uint64_t ordinal = f->event.datagrams[dir]++;
        /* Port 53 used to be captured without any limit, so a busy resolver could
           flood the analysis queue and crowd out the TLS/QUIC opening samples.
           Keep a generous but finite budget instead. */
        int dns = f->event.flow.dport == 53 || f->event.flow.sport == 53;
        if (ordinal >= (dns ? 256u : 32u)) {
            f->event.flags[dir] |= WD_FLAG_BUDGET;
            return;
        }
        size_t n = len < WD_CAPTURE_CHUNK ? len : WD_CAPTURE_CHUNK;
        if (n < len) f->event.flags[dir] |= WD_FLAG_TRUNCATED;
        f->event.offered[dir]++;
        emit(c, f, WD_UDP_DATAGRAM,
             dir == WD_DIR_OUTBOUND ? WD_SOURCE_APP_DATAGRAM : WD_SOURCE_SERVER_DATAGRAM,
             dir, now, ordinal, data, len, n);
        return;
    }
    /* The budget starts at the first payload byte, not at SYN: apps pre-connect
       sockets and only start TLS seconds later, and a SYN-based window would miss
       the ClientHello entirely. */
    if (!f->first_data) f->first_data = now;
    size_t n = len;
    if (now - f->first_data >= 5000 || offset >= WD_CAPTURE_STREAM_BYTES) n = 0;
    else if (n > WD_CAPTURE_STREAM_BYTES - offset) n = (size_t)(WD_CAPTURE_STREAM_BYTES - offset);
    if (n < len) f->event.flags[dir] |= WD_FLAG_BUDGET;
    for (size_t copied = 0; copied < n;) {
        size_t chunk = n - copied;
        if (chunk > WD_CAPTURE_CHUNK) chunk = WD_CAPTURE_CHUNK;
        f->event.offered[dir] += chunk;
        emit(c, f, WD_TCP_DATA,
             dir == WD_DIR_OUTBOUND ? WD_SOURCE_APP_STREAM : WD_SOURCE_SERVER_STREAM,
             dir, now, offset + copied, data + copied, chunk, chunk);
        copied += chunk;
    }
}

void wd_capture_end(wd_capture *c, wd_capture_flow *f, wd_direction dir, uint64_t now) {
    if (f) emit(c, f, WD_STREAM_END, WD_SOURCE_LIFECYCLE, dir, now,
                f->event.bytes[dir], NULL, 0, 0);
}

void wd_capture_expire(wd_capture *c, uint64_t now) {
    if (!c->observer) return;
    for (size_t i = 0; i < WD_CAPTURE_FLOWS; ++i) {
        wd_capture_flow *f = &c->flows[i];
        if (f->event.flow_id && !f->bound && now - f->last_active >= 60000)
            wd_capture_close(c, f, WD_CLOSE_IDLE, now);
        else if (f->event.flow_id && now - f->last_report >= 1000) {
            emit(c, f, WD_FLOW_STATS, WD_SOURCE_LIFECYCLE, WD_DIR_OUTBOUND,
                 now, 0, NULL, 0, 0);
            f->last_report = now;
        }
    }
}
