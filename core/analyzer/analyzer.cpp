#include "analyzer.h"
#include "log.h"
#include "protocols.h"
#include "quic.h"
#include "../src/capture.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <string>

namespace linkatlas {
namespace {

uint64_t clockMs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

uint16_t be16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t be32(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
size_t be24(const uint8_t *p) { return (size_t(p[0]) << 16) | (size_t(p[1]) << 8) | p[2]; }

bool textField(char *out, const uint8_t *p, size_t len) {
    if (!len || len >= 256) return false;
    for (size_t i = 0; i < len; ++i)
        if (p[i] <= 32 || p[i] > 126) return false;
    std::memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

// Only the first plaintext HTTP/1 header block. No body retention.
bool httpHeader(const std::vector<uint8_t> &bytes, char *host) {
    std::string s(bytes.begin(), bytes.end());
    size_t end = s.find("\r\n\r\n"), first = s.find("\r\n");
    if (end == std::string::npos || first == std::string::npos) return false;
    std::string line = s.substr(0, first);
    bool response = line.rfind("HTTP/1.0 ", 0) == 0 || line.rfind("HTTP/1.1 ", 0) == 0;
    bool request = false;
    for (const char *method : {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}) {
        if (line.rfind(method, 0) == 0 &&
            (line.size() >= 9 && (line.compare(line.size() - 9, 9, " HTTP/1.1") == 0 ||
                                 line.compare(line.size() - 9, 9, " HTTP/1.0") == 0))) request = true;
    }
    if (!request && !response) return false;
    for (size_t pos = first + 2; pos < end;) {
        size_t next = s.find("\r\n", pos);
        if (next == std::string::npos) break;
        if (request && next - pos >= 5) {
            std::string name = s.substr(pos, 5);
            for (char &ch : name) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
            if (name == "host:") {
                size_t start = pos + 5, finish = next;
                while (start < finish && (s[start] == ' ' || s[start] == '\t')) ++start;
                while (finish > start && (s[finish - 1] == ' ' || s[finish - 1] == '\t')) --finish;
                textField(host, reinterpret_cast<const uint8_t *>(s.data() + start), finish - start);
            }
        }
        pos = next + 2;
    }
    return true;
}

}  // namespace

// Input is one complete handshake, after TLS record framing has been removed.
bool tlsClientHelloSni(const std::vector<uint8_t> &h, char *sni) {
    if (h.size() < 4 || (h[0] != 1 && h[0] != 2)) return false;
    size_t end = 4 + be24(h.data() + 1);
    if (end > h.size() || end < 39 || h[4] != 3) return false;
    size_t pos = 38;
    size_t session = h[pos++];
    if (session > 32 || pos + session > end) return false;
    pos += session;
    if (h[0] == 1) {
        if (pos + 2 > end) return false;
        size_t ciphers = be16(h.data() + pos);
        pos += 2;
        if (ciphers < 2 || ciphers % 2 || pos + ciphers + 1 > end) return false;
        pos += ciphers;
        size_t compression = h[pos++];
        if (!compression || pos + compression > end) return false;
        pos += compression;
    } else {
        if (pos + 3 > end) return false;
        pos += 3;
    }
    if (pos == end) return true;
    if (pos + 2 > end || pos + 2 + be16(h.data() + pos) != end) return false;
    pos += 2;
    char parsedSni[256]{};
    while (pos < end) {
        if (pos + 4 > end) return false;
        uint16_t type = be16(h.data() + pos);
        size_t len = be16(h.data() + pos + 2);
        pos += 4;
        if (pos + len > end) return false;
        if (type == 0 && h[0] == 1) {
            if (len < 2 || be16(h.data() + pos) != len - 2) return false;
            size_t name = pos + 2;
            while (name < pos + len) {
                if (name + 3 > pos + len) return false;
                uint8_t kind = h[name];
                size_t size = be16(h.data() + name + 1);
                name += 3;
                if (name + size > pos + len) return false;
                if (kind == 0 && !textField(parsedSni, h.data() + name, size)) return false;
                name += size;
            }
        }
        pos += len;
    }
    if (parsedSni[0]) std::memcpy(sni, parsedSni, sizeof(parsedSni));
    return true;
}

namespace {

bool dnsQuestion(const uint8_t *p, size_t len, char *out) {
    if (len < 12 || !be16(p + 4) || (p[2] & 0x78)) return false;
    size_t pos = 12, consumed = 0, size = 0;
    bool jumped = false, ended = false;
    char name[256]{};
    for (unsigned steps = 0; steps < 128 && pos < len; ++steps) {
        uint8_t label = p[pos++];
        if ((label & 0xc0) == 0xc0) {
            if (pos >= len) return false;
            size_t target = ((label & 0x3f) << 8) | p[pos++];
            if (!jumped) consumed = pos;
            jumped = true;
            if (target >= len) return false;
            pos = target;
            continue;
        }
        if (label & 0xc0) return false;
        if (!label) {
            if (!jumped) consumed = pos;
            ended = true;
            break;
        }
        if (pos + label > len || size + label + (size ? 1 : 0) > 253) return false;
        if (size) name[size++] = '.';
        for (size_t i = 0; i < label; ++i) {
            if (p[pos] <= 32 || p[pos] > 126) return false;
            name[size++] = static_cast<char>(p[pos++]);
        }
    }
    if (!ended || consumed + 4 > len) return false;
    if (!size) name[size++] = '.';
    name[size] = '\0';
    std::memcpy(out, name, sizeof(name));
    return true;
}

} // namespace

void Analyzer::stopParsing(Direction &d) {
    if (d.allocated) {
        --parsing_directions_;
        d.allocated = false;
    }
    d.stopped = true;
    std::vector<uint8_t>().swap(d.prefix);
    std::vector<uint8_t>().swap(d.handshake);
}

ObservationQueue::ObservationQueue() : slots_(new Slot[Size]) {}

bool ObservationQueue::push(const wd_event &event) {
    /* The opening bytes of every direction carry the only domain evidence there is
       (TLS ClientHello, HTTP request line, QUIC Initial). Keep them out of the
       ordinary data budget so a full queue cannot blind a flow for good. */
    bool control = event.type == WD_FLOW_OPEN || event.type == WD_FLOW_CLOSE ||
                   event.type == WD_STREAM_END || event.offset == 0;
    if (unsigned(event.direction) > WD_DIR_INBOUND || unsigned(event.type) > WD_FLOW_STATS ||
        unsigned(event.source) > WD_SOURCE_LIFECYCLE || event.captured > WD_CAPTURE_CHUNK ||
        event.captured > event.length || (event.captured && !event.data)) {
        return false;
    }
    uint64_t head = head_.load(std::memory_order_relaxed);
    uint64_t used = head - tail_.load(std::memory_order_acquire);
    if (used >= (control ? Size : Size - ControlReserve)) return false;
    Slot &slot = slots_[head % Size];
    slot.event = event;
    if (event.captured) std::memcpy(slot.data.data(), event.data, event.captured);
    slot.event.data = slot.data.data();
    head_.store(head + 1, std::memory_order_release);
    return true;
}

const wd_event *ObservationQueue::peek() {
    uint64_t tail = tail_.load(std::memory_order_relaxed);
    return tail == head_.load(std::memory_order_acquire) ? nullptr : &slots_[tail % Size].event;
}

void ObservationQueue::pop() {
    tail_.store(tail_.load(std::memory_order_relaxed) + 1, std::memory_order_release);
}

Analyzer::Analyzer() : worker_(&Analyzer::run, this) {}

Analyzer::~Analyzer() {
    stopping_.store(true, std::memory_order_release);
    wake_.notify_one();
    worker_.join();
}

void Analyzer::onEvent(const wd_event &event) {
    if (!queue_.push(event)) {
        /* The opening bytes of every direction carry the only domain evidence there is
       (TLS ClientHello, HTTP request line, QUIC Initial). Keep them out of the
       ordinary data budget so a full queue cannot blind a flow for good. */
    bool control = event.type == WD_FLOW_OPEN || event.type == WD_FLOW_CLOSE ||
                   event.type == WD_STREAM_END || event.offset == 0;
        (control ? dropped_control_ : dropped_data_).fetch_add(1, std::memory_order_relaxed);
        return;
    }
    enqueued_.fetch_add(1, std::memory_order_relaxed);
    wake_.notify_one();
}

void Analyzer::parseStream(Flow &f, const wd_event &e) {
    auto &d = f.directions[e.direction];
    if (e.offset != d.next) {
        f.result.flags[e.direction] |= WD_FLAG_GAP;
        stopParsing(d);
    }
    d.next = e.offset + e.length;
    if (e.captured != e.length) {
        f.result.flags[e.direction] |= WD_FLAG_TRUNCATED;
        stopParsing(d);
    }
    if (d.stopped) return;
    /* The server side never yields a domain: HTTP responses carry no Host and the
       TLS ServerHello only confirms the protocol. Sniff the opening bytes without
       taking a parsing slot, which was otherwise held for the whole capture budget
       and exhausted the direction cache on a busy device. */
    if (e.direction == WD_DIR_INBOUND) {
        if (e.captured >= 6 && e.data[0] == 22 && e.data[1] == 3 && e.data[2] <= 4)
            f.result.protocol[WD_DIR_INBOUND] = WD_PROTOCOL_TLS;
        else if (e.captured >= 7 && !std::memcmp(e.data, "HTTP/1.", 7))
            f.result.protocol[WD_DIR_INBOUND] = WD_PROTOCOL_HTTP;
        stopParsing(d);
        return;
    }
    if (!d.allocated) {
        if (parsing_directions_ >= MaxParsingDirections) {
            f.result.flags[e.direction] |= WD_FLAG_CAPACITY;
            stopParsing(d);
            return;
        }
        d.allocated = true;
        ++parsing_directions_;
        d.prefix.reserve(4096);
    }
    /* Drop TLS records already handed to the handshake buffer: a long-lived
       connection then retains a few KiB instead of the whole capture budget. */
    if (d.tls_cursor >= 4096 && d.tls_cursor <= d.prefix.size()) {
        d.prefix.erase(d.prefix.begin(), d.prefix.begin() + d.tls_cursor);
        d.tls_cursor = 0;
    }
    if (d.prefix.size() + e.captured > MaxHandshakeBytes) {
        f.result.flags[e.direction] |= WD_FLAG_CAPACITY;
        stopParsing(d);
        return;
    }
    d.prefix.insert(d.prefix.end(), e.data, e.data + e.captured);
    auto &p = d.prefix;
    if (p.empty()) return;
    if (!d.tls) {
        if (p[0] != 22) {
            if (httpHeader(p, f.result.http_host)) {
                f.result.protocol[e.direction] = WD_PROTOCOL_HTTP;
                stopParsing(d);
            }
            return;
        }
        d.tls = true;
    }
    while (d.tls_cursor + 5 <= p.size()) {
        size_t pos = d.tls_cursor;
        size_t len = be16(p.data() + pos + 3);
        if (p[pos] != 22 || p[pos + 1] != 3 || p[pos + 2] > 4 || !len || len > 18432) {
            stopParsing(d);
            return;
        }
        if (pos + 5 + len > p.size()) return;
        if (d.handshake.capacity() == 0) d.handshake.reserve(4096);
        d.handshake.insert(d.handshake.end(), p.begin() + pos + 5, p.begin() + pos + 5 + len);
        d.tls_cursor = pos + 5 + len;
        if (d.handshake.size() >= 4) {
            size_t needed = 4 + be24(d.handshake.data() + 1);
            if (needed > MaxHandshakeBytes) {
                f.result.flags[e.direction] |= WD_FLAG_CAPACITY;
                stopParsing(d);
                return;
            }
            if (d.handshake.size() >= needed) {
                if (tlsClientHelloSni(d.handshake, f.result.tls_sni)) {
                    f.result.protocol[e.direction] = WD_PROTOCOL_TLS;
                    logf("sni tcp flow=%llu sni=%s", (unsigned long long)f.result.flow_id,
                         f.result.tls_sni[0] ? f.result.tls_sni : "-");
                }
                stopParsing(d);
                return;
            }
        }
    }
}

// Decodes a (possibly compressed) DNS name; off ends just past the wire bytes.
static bool dnsName(const uint8_t *m, size_t len, size_t &off, char *out) {
    size_t pos = off, outlen = 0;
    bool jumped = false;
    out[0] = 0;
    for (int guard = 0; guard < 8; ++guard) {
        if (pos >= len) return false;
        uint8_t n = m[pos];
        if (n == 0) { if (!jumped) off = pos + 1; return true; }
        if ((n & 0xc0) == 0xc0) {
            if (pos + 1 >= len) return false;
            size_t ptr = ((n & 0x3f) << 8) | m[pos + 1];
            if (ptr >= len) return false;
            if (!jumped) { off = pos + 2; jumped = true; }
            pos = ptr;
            continue;
        }
        if (n & 0xc0 || pos + 1 + n > len || outlen + n + 1 >= 255) return false;
        if (outlen) out[outlen++] = '.';
        std::memcpy(out + outlen, m + pos + 1, n);
        outlen += n;
        out[outlen] = 0;
        pos += 1 + n;
    }
    return false;
}

void Analyzer::process(const wd_event &e) {
    ++stats_.processed;
    if (!e.flow_id) {
        if (e.type == WD_PACKET) ++stats_.unassociated_packets;
        return;
    }
    auto it = flows_.find(e.flow_id);
    if (it == flows_.end()) {
        if (flows_.size() >= MaxFlows) {
            auto oldest = std::min_element(flows_.begin(), flows_.end(), [](const auto &a, const auto &b) {
                if (a.second.result.closed != b.second.result.closed) return a.second.result.closed > b.second.result.closed;
                return a.second.touched < b.second.touched;
            });
            stopParsing(oldest->second.directions[0]);
            stopParsing(oldest->second.directions[1]);
            flows_.erase(oldest);
            ++stats_.evicted_flows;
        }
        it = flows_.try_emplace(e.flow_id).first;
        it->second.result.flow_id = e.flow_id;
        it->second.result.flow = e.flow;
        it->second.result.first_seen_ms = e.timestamp_ms;
        if (e.type != WD_FLOW_OPEN)
            it->second.result.flags[0] = it->second.result.flags[1] = WD_FLAG_GAP;
    }
    Flow &f = it->second;
    f.touched = clockMs();
    auto &r = f.result;
    r.analysis_expired = 0;
    r.last_seen_ms = e.timestamp_ms;
    r.sources |= 1u << e.source;
    r.app_packets = e.app_packets;
    r.app_packet_bytes = e.app_packet_bytes;
    if (e.app_packets > 32) r.packet_flags |= WD_FLAG_BUDGET;
    for (int dir = 0; dir < 2; ++dir) {
        r.bytes[dir] = e.bytes[dir];
        r.datagrams[dir] = e.datagrams[dir];
        r.flags[dir] |= e.flags[dir];
    }
    if (e.type == WD_PACKET && e.source == WD_SOURCE_APP_PACKET) {
        ++r.packet_samples;
        if (e.offset != f.next_packet) r.packet_flags |= WD_FLAG_GAP;
        f.next_packet = e.offset + 1;
        if (e.captured < e.length) r.packet_flags |= WD_FLAG_TRUNCATED;
        wd_flow_key key{};
        size_t off;
        if (wd_packet_key(e.data, e.captured, 1, &key, &off)) {
            r.app_hop_limit = key.ipver == 4 ? e.data[8] : e.data[7];
            if (key.proto == WD_PROTO_TCP && (e.data[off + 13] & 0x12) == 2 && !r.app_tcp_syn_seen) {
                r.app_tcp_syn_seen = 1;
                r.app_tcp_window = be16(e.data + off + 14);
                size_t options = (e.data[off + 12] >> 4) * 4u - 20;
                r.app_tcp_options_len = static_cast<uint8_t>(options);
                std::memcpy(r.app_tcp_options, e.data + off + 20, options);
            }
        }
    } else if (e.type == WD_TCP_DATA) {
        f.received[e.direction] += e.captured;
        parseStream(f, e);
    } else if (e.type == WD_UDP_DATAGRAM) {
        ++f.received[e.direction];
        auto &d = f.directions[e.direction];
        if (e.offset != d.next) r.flags[e.direction] |= WD_FLAG_GAP;
        d.next = e.offset + 1;
        if (e.captured != e.length) r.flags[e.direction] |= WD_FLAG_TRUNCATED;
        else if (e.flow.dport == 53 || e.flow.sport == 53) {
            if (dnsQuestion(e.data, e.captured, r.dns_question))
                r.protocol[e.direction] = WD_PROTOCOL_DNS;
            parseDnsAnswers(e.data, e.captured, e.timestamp_ms);
        } else if (e.flow.dport == 443 && e.direction == WD_DIR_OUTBOUND && !f.quicOut.done) {
            /* QUIC Initial keys derive from the plaintext DCID, so the client's
               ClientHello - and its SNI - is recoverable without any secret. */
            char quicSni[256]{};
            if (quicClientHelloSni(e.data, e.captured, f.quicOut, quicSni) && quicSni[0]) {
                if (!r.tls_sni[0]) std::memcpy(r.tls_sni, quicSni, sizeof(quicSni));
                r.protocol[e.direction] = WD_PROTOCOL_QUIC;
                logf("sni quic flow=%llu sni=%s", (unsigned long long)e.flow_id, quicSni);
            }
        }
    } else if (e.type == WD_FLOW_STATS) {
        for (int dir = 0; dir < 2; ++dir) {
            if (e.flow.proto == WD_PROTO_TCP && !f.directions[dir].stopped &&
                (e.timestamp_ms - r.first_seen_ms >= 5000 || e.flags[dir] & WD_FLAG_BUDGET)) {
                r.flags[dir] |= WD_FLAG_BUDGET;
                stopParsing(f.directions[dir]);
            }
        }
    } else if (e.type == WD_STREAM_END || e.type == WD_FLOW_CLOSE) {
        for (int dir = 0; dir < 2; ++dir) {
            if (e.type == WD_STREAM_END && dir != e.direction) continue;
            if (f.received[dir] != e.offered[dir])
                r.flags[dir] |= WD_FLAG_GAP;
            stopParsing(f.directions[dir]);
        }
        if (e.type == WD_FLOW_CLOSE) {
            r.closed = 1;
            r.close_reason = e.close_reason;
            if (f.next_packet != std::min<uint64_t>(e.app_packets, 32)) r.packet_flags |= WD_FLAG_GAP;
        }
    }
    // offered counters distinguish queue loss from intentional sampling limits,
    // including a dropped final sample with no later data in that direction.
    for (int dir = 0; dir < 2; ++dir) {
        if (f.received[dir] < e.offered[dir]) {
            r.flags[dir] |= WD_FLAG_GAP;
            if (e.flow.proto == WD_PROTO_TCP) stopParsing(f.directions[dir]);
        }
    }
    /* Port 53 is resolver traffic regardless of parse success: TCP DNS carries a
       length prefix the TLS parser can mistake for a record header, and truncated
       UDP datagrams may not decode as questions. Never surface it as a "service". */
    if (e.flow.dport == 53 || e.flow.sport == 53) {
        r.protocol[0] = WD_PROTOCOL_DNS;
        r.protocol[1] = WD_PROTOCOL_DNS;
    }
    recordDestination(f, e);
    /* One line per closed flow: enough to tell "no payload" from "payload but no
       name" without putting diagnostics into the UI. Resolver traffic is skipped,
       it is infrastructure and never carries a destination name. */
    if (e.type == WD_FLOW_CLOSE && r.protocol[0] != WD_PROTOCOL_DNS) {
        char text[80];
        if (r.flow.ipver == 6) {
            std::snprintf(text, sizeof(text),
                          "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                          r.flow.dst[0], r.flow.dst[1], r.flow.dst[2], r.flow.dst[3],
                          r.flow.dst[4], r.flow.dst[5], r.flow.dst[6], r.flow.dst[7],
                          r.flow.dst[8], r.flow.dst[9], r.flow.dst[10], r.flow.dst[11],
                          r.flow.dst[12], r.flow.dst[13], r.flow.dst[14], r.flow.dst[15]);
        } else {
            std::snprintf(text, sizeof(text), "%u.%u.%u.%u", r.flow.dst[0], r.flow.dst[1],
                          r.flow.dst[2], r.flow.dst[3]);
        }
        unsigned all = r.flags[0] | r.flags[1] | r.packet_flags;
        logf("flow %llu %s %s out=%llu in=%llu proto=%u domain=%s src=%u gap=%u cap=%u trunc=%u budget=%u",
             (unsigned long long)r.flow_id, r.flow.proto == WD_PROTO_TCP ? "tcp" : "udp", text,
             (unsigned long long)r.bytes[0], (unsigned long long)r.bytes[1],
             unsigned(r.protocol[0] ? r.protocol[0] : r.protocol[1]),
             f.sticky_domain.empty() ? "-" : f.sticky_domain.c_str(), unsigned(f.sticky_source),
             (all & WD_FLAG_GAP) ? 1u : 0u, (all & WD_FLAG_CAPACITY) ? 1u : 0u,
             (all & WD_FLAG_TRUNCATED) ? 1u : 0u, (all & WD_FLAG_BUDGET) ? 1u : 0u);
    }
}

void Analyzer::parseDnsAnswers(const uint8_t *m, size_t len, uint64_t now) {
    if (len < 12 || !(m[2] & 0x80)) return; // responses only
    size_t qd = be16(m + 4), an = be16(m + 6);
    if (!qd) return;
    size_t off = 12;
    char qname[256];
    if (!dnsName(m, len, off, qname) || !qname[0]) return;
    for (size_t q = 0; q < qd; ++q) {
        if (q && !dnsName(m, len, off, qname)) return;
        if (off + 4 > len) return;
        off += 4;
    }
    for (size_t i = 0; i < an; ++i) {
        char owner[256];
        if (!dnsName(m, len, off, owner) || off + 10 > len) return;
        uint16_t type = be16(m + off), rdlen = be16(m + off + 8);
        uint32_t ttl = be32(m + off + 4);
        off += 10;
        if (off + rdlen > len) return;
        if ((type == 1 && rdlen == 4) || (type == 28 && rdlen == 16))
            recordDns(type == 1 ? 4 : 6, m + off, rdlen, qname, ttl, now);
        off += rdlen;
    }
}

void Analyzer::recordDns(uint8_t ver, const uint8_t *addr, size_t addrLen,
                         const std::string &name, uint32_t ttl, uint64_t now) {
    if (name.empty() || dns_map_.size() >= 4096) return;
    std::string key(1, static_cast<char>(ver));
    key.append(reinterpret_cast<const char *>(addr), addrLen);
    DnsEntry &e = dns_map_[key];
    e.name = name;
    e.resolved_ms = now;
    e.expiry_ms = now + std::min<uint64_t>(ttl, 3600) * 1000;
    /* Keep the name around well past its TTL so a connection that starts later
       can still be attributed: "this IP was the answer for that name a moment
       ago". Freshness only matters for the resolver, not for reverse lookup. */
    e.retain_ms = now + std::max<uint64_t>(std::min<uint64_t>(ttl, 3600), 1800) * 1000;
}

std::string Analyzer::dnsLookup(uint8_t ver, const uint8_t *dst, uint64_t now) {
    std::string key(1, static_cast<char>(ver));
    key.append(reinterpret_cast<const char *>(dst), ver == 6 ? 16 : 4);
    auto it = dns_map_.find(key);
    if (it == dns_map_.end()) return {};
    if (now > it->second.retain_ms) {
        dns_map_.erase(it);
        return {};
    }
    return it->second.name;
}

void Analyzer::recordDestination(Flow &f, const wd_event &event) {
    // Rehydrating an evicted flow from later stats/data must not count it again.
    if (f.destination_key.empty() && event.type != WD_FLOW_OPEN) return;
    const auto &r = f.result;
    if (r.flow.proto != WD_PROTO_TCP && r.flow.proto != WD_PROTO_UDP) return;
    uint8_t source = 0;
    std::string domain;
    if (r.tls_sni[0]) { domain = r.tls_sni; source = 1; }
    else if (r.http_host[0]) { domain = r.http_host; source = 2; }
    else {
        domain = dnsLookup(r.flow.ipver, r.flow.dst, event.timestamp_ms);
        if (!domain.empty()) source = 3;
    }
    for (char &c : domain) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    // Passive-DNS entries expire with their TTL, but a transfer that outlives
    // that TTL must keep the name it already earned instead of dumping its whole
    // byte total onto a bare IP. Retain the best attribution seen for this flow;
    // a lower-numbered source is stronger, so SNI / Host still upgrade it.
    if (source && (!f.sticky_source || source <= f.sticky_source)) {
        f.sticky_domain = domain;
        f.sticky_source = source;
    }
    domain = f.sticky_domain;
    source = f.sticky_source;
    std::string key(1, static_cast<char>(r.flow.ipver));
    key.append(reinterpret_cast<const char *>(r.flow.dst), r.flow.ipver == 6 ? 16 : 4);
    key += domain;
    if (key != f.destination_key) {
        // Allocate before moving the count, so allocation failure cannot lose a visit.
        auto &destination = destinations_[key];
        destination.ipver = r.flow.ipver;
        std::memcpy(destination.dst, r.flow.dst, sizeof(destination.dst));
        std::memcpy(destination.domain, domain.c_str(), domain.size() + 1);
        destination.domain_source = source;
        if (r.flow.proto == WD_PROTO_TCP) ++destination.tcp_connections;
        else ++destination.udp_flows;
        if (!f.destination_key.empty()) {
            auto previous = destinations_.find(f.destination_key);
            if (previous != destinations_.end()) {
                auto &p = previous->second;
                if (r.flow.proto == WD_PROTO_TCP) --p.tcp_connections;
                else --p.udp_flows;
                for (int dir = 0; dir < 2; ++dir) {
                    p.bytes[dir] -= std::min(p.bytes[dir], f.attributed_bytes[dir]);
                    destination.bytes[dir] += f.attributed_bytes[dir];
                }
                if (!p.tcp_connections && !p.udp_flows) destinations_.erase(previous);
            }
        }
        f.destination_key = std::move(key);
    }
    auto &destination = destinations_[f.destination_key];
    for (int dir = 0; dir < 2; ++dir) {
        if (r.bytes[dir] > f.attributed_bytes[dir]) {
            destination.bytes[dir] += r.bytes[dir] - f.attributed_bytes[dir];
            f.attributed_bytes[dir] = r.bytes[dir];
        }
    }
    wd_protocol proto = r.protocol[0] != WD_PROTOCOL_UNKNOWN ? r.protocol[0] : r.protocol[1];
    if (proto != WD_PROTOCOL_UNKNOWN) destination.protocol = static_cast<uint8_t>(proto);
    if (r.app_tcp_syn_seen) {
        destination.has_fingerprint = 1;
        destination.app_hop_limit = r.app_hop_limit;
        destination.app_tcp_window = r.app_tcp_window;
        destination.app_tcp_options_len = r.app_tcp_options_len;
        std::memcpy(destination.app_tcp_options, r.app_tcp_options, r.app_tcp_options_len);
    }
}

void Analyzer::expire(uint64_t now) {
    for (auto it = dns_map_.begin(); it != dns_map_.end();) {
        if (now > it->second.retain_ms) it = dns_map_.erase(it);
        else ++it;
    }
    for (auto it = flows_.begin(); it != flows_.end();) {
        Flow &f = it->second;
        if (now - f.touched >= 120000) {
            if (f.result.closed || f.result.analysis_expired) {
                it = flows_.erase(it);
                continue;
            }
            f.result.flags[0] |= WD_FLAG_EXPIRED;
            f.result.flags[1] |= WD_FLAG_EXPIRED;
            f.result.analysis_expired = 1;
            stopParsing(f.directions[0]);
            stopParsing(f.directions[1]);
            f.touched = now;
            ++stats_.expired_flows;
        }
        ++it;
    }
}

void Analyzer::run() {
    uint64_t lastCleanup = clockMs();
    for (;;) {
        if (const wd_event *event = queue_.peek()) {
            {
                std::lock_guard<std::mutex> lock(results_mutex_);
                try {
                    process(*event);
                } catch (...) {
                    ++stats_.parser_failures;
                    auto it = flows_.find(event->flow_id);
                    if (it != flows_.end()) {
                        it->second.result.flags[0] |= WD_FLAG_CAPACITY;
                        it->second.result.flags[1] |= WD_FLAG_CAPACITY;
                        stopParsing(it->second.directions[0]);
                        stopParsing(it->second.directions[1]);
                    }
                }
            }
            queue_.pop();
        } else {
            if (stopping_.load(std::memory_order_acquire)) break;
            // Timed wait also handles a notification arriving before the wait.
            std::unique_lock<std::mutex> lock(wake_mutex_);
            wake_.wait_for(lock, std::chrono::milliseconds(10));
        }
        uint64_t now = clockMs();
        if (now - lastCleanup >= 1000) {
            std::lock_guard<std::mutex> lock(results_mutex_);
            expire(now);
            lastCleanup = now;
        }
    }
}

size_t Analyzer::snapshot(wd_flow_summary *out, size_t capacity) {
    if (!out || !capacity) return 0;
    std::lock_guard<std::mutex> lock(results_mutex_);
    std::vector<const Flow *> ordered;
    ordered.reserve(flows_.size());
    for (const auto &entry : flows_) ordered.push_back(&entry.second);
    std::sort(ordered.begin(), ordered.end(), [](const Flow *a, const Flow *b) {
        return a->result.flow_id > b->result.flow_id;
    });
    size_t n = std::min(capacity, ordered.size());
    for (size_t i = 0; i < n; ++i) out[i] = ordered[i]->result;
    return n;
}

void Analyzer::reset() {
    std::lock_guard<std::mutex> lock(results_mutex_);
    flows_.clear();
    destinations_.clear();
    dns_map_.clear();
    parsing_directions_ = 0;
    stats_ = wd_analyzer_stats{};
    enqueued_.store(0, std::memory_order_relaxed);
    dropped_data_.store(0, std::memory_order_relaxed);
    dropped_control_.store(0, std::memory_order_relaxed);
}

void Analyzer::stats(wd_analyzer_stats &out) {
    std::lock_guard<std::mutex> lock(results_mutex_);
    out = stats_;
    out.enqueued = enqueued_.load(std::memory_order_relaxed);
    out.dropped_data = dropped_data_.load(std::memory_order_relaxed);
    out.dropped_control = dropped_control_.load(std::memory_order_relaxed);
}

size_t Analyzer::destinations(wd_destination_summary *out, size_t capacity) {
    std::lock_guard<std::mutex> lock(results_mutex_);
    size_t copied = 0;
    if (out) {
        for (const auto &entry : destinations_) {
            if (copied == capacity) break;
            out[copied++] = entry.second;
        }
    }
    return destinations_.size();
}

} // namespace linkatlas

extern "C" {

void *wd_analyzer_create(void) {
    try { return new linkatlas::Analyzer(); } catch (...) { return nullptr; }
}
void wd_analyzer_destroy(void *analyzer) { delete static_cast<linkatlas::Analyzer *>(analyzer); }
void wd_analyzer_on_event(void *analyzer, const wd_event *event) {
    if (analyzer && event) static_cast<linkatlas::Analyzer *>(analyzer)->onEvent(*event);
}
size_t wd_analyzer_snapshot(void *analyzer, wd_flow_summary *out, size_t capacity) {
    if (!analyzer) return 0;
    try { return static_cast<linkatlas::Analyzer *>(analyzer)->snapshot(out, capacity); }
    catch (...) { return 0; }
}
size_t wd_analyzer_destinations(void *analyzer, wd_destination_summary *out, size_t capacity) {
    if (!analyzer) return 0;
    return static_cast<linkatlas::Analyzer *>(analyzer)->destinations(out, capacity);
}
void wd_analyzer_reset(void *analyzer) {
    if (!analyzer) return;
    try { static_cast<linkatlas::Analyzer *>(analyzer)->reset(); } catch (...) {}
}
void wd_analyzer_get_stats(void *analyzer, wd_analyzer_stats *out) {
    if (out) {
        *out = {};
        if (analyzer) static_cast<linkatlas::Analyzer *>(analyzer)->stats(*out);
    }
}

}
