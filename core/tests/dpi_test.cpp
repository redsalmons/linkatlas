#include "linkatlas/analyzer.h"
#include "../src/capture.h"
#include "../analyzer/analyzer.h"
#include "../analyzer/crypto.h"
#include "../analyzer/quic.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); std::abort(); \
} } while (0)

using Bytes = std::vector<uint8_t>;

static void put16(Bytes &b, size_t at, uint16_t n) { b[at] = n >> 8; b[at + 1] = n; }
static void put32(Bytes &b, size_t at, uint32_t n) { put16(b, at, n >> 16); put16(b, at + 2, n); }
static uint16_t get16(const uint8_t *p) { return uint16_t((p[0] << 8) | p[1]); }
static uint32_t get32(const uint8_t *p) { return (uint32_t(get16(p)) << 16) | get16(p + 2); }

static void waitFor(const std::function<bool()> &predicate) {
    auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!predicate()) {
        CHECK(std::chrono::steady_clock::now() < until);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
}

static Bytes ipPacket(uint16_t port, uint8_t protocol, const Bytes &transport, bool v6 = false) {
    size_t header = v6 ? 40 : 20;
    Bytes p(header + transport.size());
    p[0] = v6 ? 0x60 : 0x45;
    if (v6) {
        put16(p, 4, transport.size());
        p[6] = protocol;
        p[7] = 63;
        p[8] = 0xfd;
        p[23] = 2;
        p[39] = 1; // ::1
    } else {
        put16(p, 2, p.size());
        p[8] = 63;
        p[9] = protocol;
        p[12] = 10; p[13] = 8; p[15] = 2;
        p[16] = 127; p[19] = 1;
    }
    std::copy(transport.begin(), transport.end(), p.begin() + header);
    put16(p, header, 40123);
    put16(p, header + 2, port);
    return p;
}

static Bytes tcpPacket(uint16_t port, uint32_t seq, uint32_t ack, uint8_t flags,
                       const std::string &data = "", bool v6 = false) {
    size_t header = flags & 2 ? 24 : 20;
    Bytes tcp(header + data.size());
    put32(tcp, 4, seq);
    put32(tcp, 8, ack);
    tcp[12] = uint8_t((header / 4) << 4);
    tcp[13] = flags;
    put16(tcp, 14, 60000);
    if (flags & 2) { tcp[20] = 2; tcp[21] = 4; put16(tcp, 22, 1400); }
    std::copy(data.begin(), data.end(), tcp.begin() + header);
    return ipPacket(port, WD_PROTO_TCP, tcp, v6);
}

static Bytes udpPacket(uint16_t port, const Bytes &data, bool v6 = false) {
    Bytes udp(8 + data.size());
    put16(udp, 4, udp.size());
    std::copy(data.begin(), data.end(), udp.begin() + 8);
    return ipPacket(port, WD_PROTO_UDP, udp, v6);
}

struct SavedEvent {
    wd_event event;
    Bytes data;
    explicit SavedEvent(const wd_event &e) : event(e) {
        if (e.captured) data.assign(e.data, e.data + e.captured);
        event.data = nullptr;
    }
};

struct CaptureFixture {
    void *analyzer = wd_analyzer_create();
    wd_capture capture{};
    std::vector<SavedEvent> events;
    CaptureFixture() {
        CHECK(analyzer);
        capture.ctx = this;
        capture.observer = [](void *ctx, const wd_event *e) {
            auto &self = *static_cast<CaptureFixture *>(ctx);
            self.events.emplace_back(*e);
            wd_analyzer_on_event(self.analyzer, e);
        };
    }
    ~CaptureFixture() { wd_analyzer_destroy(analyzer); }
    std::vector<wd_flow_summary> results() {
        waitFor([&] {
            wd_analyzer_stats s{};
            wd_analyzer_get_stats(analyzer, &s);
            return s.enqueued == s.processed;
        });
        std::vector<wd_flow_summary> out(256);
        out.resize(wd_analyzer_snapshot(analyzer, out.data(), out.size()));
        return out;
    }
    wd_capture_flow *open(const Bytes &p, uint64_t now = 10) {
        wd_capture_packet(&capture, p.data(), p.size(), now);
        wd_flow_key key{};
        size_t off;
        CHECK(wd_packet_key(p.data(), p.size(), 0, &key, &off));
        return wd_capture_bind(&capture, &key, now);
    }
};

static void queueTest() {
    linkatlas::ObservationQueue q;
    Bytes data(4096, 0xab);
    wd_event e{};
    e.type = WD_TCP_DATA;
    e.data = data.data();
    e.length = e.captured = data.size();
    for (size_t i = 0; i < q.Size - q.ControlReserve; ++i) {
        e.offset = i;
        CHECK(q.push(e));
    }
    CHECK(!q.push(e));
    e.type = WD_FLOW_CLOSE;
    e.captured = e.length = 0;
    for (size_t i = 0; i < q.ControlReserve; ++i) CHECK(q.push(e));
    CHECK(!q.push(e));
    std::fill(data.begin(), data.end(), 0); // verify owned copies, not borrowed buffers
    for (size_t i = 0; i < q.Size; ++i) {
        auto *event = q.peek();
        CHECK(event);
        if (i < q.Size - q.ControlReserve) {
            CHECK(event->offset == i);
            CHECK(event->data[0] == 0xab && event->data[4095] == 0xab);
        } else CHECK(event->type == WD_FLOW_CLOSE);
        q.pop();
    }
    CHECK(!q.peek());
    CHECK(q.push(e)); // wraparound
    CHECK(q.peek()->type == WD_FLOW_CLOSE);
    q.pop();
    e.captured = 4097;
    CHECK(!q.push(e));

    // Two threads repeatedly reuse slots; data must remain ordered and owned.
    constexpr uint64_t count = 20000;
    std::thread producer([&] {
        for (uint64_t i = 0; i < count; ++i) {
            wd_event event{};
            event.type = WD_TCP_DATA;
            event.offset = i;
            event.data = reinterpret_cast<const uint8_t *>(&i);
            event.length = event.captured = sizeof(i);
            while (!q.push(event)) std::this_thread::yield();
        }
    });
    for (uint64_t i = 0; i < count; ++i) {
        const wd_event *event;
        while (!(event = q.peek())) std::this_thread::yield();
        uint64_t payload;
        std::memcpy(&payload, event->data, sizeof(payload));
        CHECK(event->offset == i && payload == i);
        q.pop();
    }
    producer.join();
}

static void packetAndIdentityTest() {
    CaptureFixture f;
    Bytes p = tcpPacket(443, 100, 0, 2);
    wd_capture_packet(&f.capture, p.data(), p.size(), 10);
    uint64_t first = f.events.front().event.flow_id;
    wd_capture_packet(&f.capture, p.data(), p.size(), 11);
    CHECK(f.events.back().event.flow_id == first);
    put32(p, 24, 200);
    wd_capture_packet(&f.capture, p.data(), p.size(), 12);
    CHECK(f.events.back().event.flow_id != first);
    CHECK(f.events[3].event.type == WD_FLOW_CLOSE);
    wd_flow_key key{};
    size_t off;
    for (size_t len = 0; len < p.size(); ++len)
        CHECK(!wd_packet_key(p.data(), len, 0, &key, &off));
    put16(p, 6, 0x2000);
    wd_capture_packet(&f.capture, p.data(), p.size(), 13);
    CHECK(f.events.back().event.flow_id == 0);
    CHECK(f.events.back().event.flags[0] & WD_FLAG_UNASSOCIATED);
    p = tcpPacket(443, 100, 0, 2, "", true);
    CHECK(wd_packet_key(p.data(), p.size(), 0, &key, &off) && off == 40);
    Bytes extension(8);
    extension[0] = WD_PROTO_TCP;
    p.insert(p.begin() + 40, extension.begin(), extension.end());
    p[6] = 0;
    put16(p, 4, p.size() - 40);
    CHECK(wd_packet_key(p.data(), p.size(), 0, &key, &off) && off == 48);
    p[6] = 44;
    CHECK(!wd_packet_key(p.data(), p.size(), 0, &key, &off));
    auto results = f.results();
    CHECK(results.size() == 2);
    CHECK(results.front().app_tcp_syn_seen);
    CHECK(results.front().app_tcp_options_len == 4);
    CHECK(results.front().app_tcp_window == 60000);
    CHECK(results.front().app_hop_limit == 63);
}

static Bytes clientHello() {
    std::string name = "example.test";
    Bytes h(4 + 2 + 32 + 1);
    h[0] = 1;
    h[4] = 3; h[5] = 3;
    h.insert(h.end(), {0, 2, 0x13, 1, 1, 0});
    size_t ext = h.size();
    h.resize(h.size() + 11);
    put16(h, ext, 9 + name.size());
    put16(h, ext + 2, 0);
    put16(h, ext + 4, 5 + name.size());
    put16(h, ext + 6, 3 + name.size());
    h[ext + 8] = 0;
    put16(h, ext + 9, name.size());
    h.insert(h.end(), name.begin(), name.end());
    h[1] = uint8_t((h.size() - 4) >> 16);
    put16(h, 2, h.size() - 4);
    Bytes record;
    // The handshake itself crosses TLS records, and later TCP observations.
    for (size_t pos = 0; pos < h.size();) {
        size_t len = std::min<size_t>(23, h.size() - pos);
        record.insert(record.end(), {22, 3, 1, uint8_t(len >> 8), uint8_t(len)});
        record.insert(record.end(), h.begin() + pos, h.begin() + pos + len);
        pos += len;
    }
    return record;
}

static void protocolTest() {
    CaptureFixture f;
    auto *flow = f.open(tcpPacket(80, 100, 0, 2));
    CHECK(flow);
    std::string http = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    for (size_t i = 0; i < http.size(); ++i)
        wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND,
                        reinterpret_cast<const uint8_t *>(http.data() + i), 1, 11);
    std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    wd_capture_data(&f.capture, flow, WD_DIR_INBOUND,
                    reinterpret_cast<const uint8_t *>(response.data()), response.size(), 12);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 13);
    auto r = f.results().front();
    CHECK(r.protocol[0] == WD_PROTOCOL_HTTP && r.protocol[1] == WD_PROTOCOL_HTTP);
    CHECK(std::string(r.http_host) == "example.test");
    CHECK(r.bytes[0] == http.size() && r.bytes[1] == response.size());
    CHECK(r.closed && !r.flags[0] && !r.flags[1]);

    flow = f.open(tcpPacket(443, 100, 0, 2));
    Bytes tls = clientHello();
    for (size_t pos = 0; pos < tls.size();) {
        size_t n = std::min<size_t>(7, tls.size() - pos);
        wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, tls.data() + pos, n, 11);
        pos += n;
    }
    Bytes serverHello(47);
    serverHello[0] = 22; serverHello[1] = 3; serverHello[2] = 3;
    put16(serverHello, 3, 42);
    serverHello[5] = 2;
    put16(serverHello, 7, 38);
    serverHello[9] = 3; serverHello[10] = 3;
    put16(serverHello, 44, 0x1301);
    wd_capture_data(&f.capture, flow, WD_DIR_INBOUND, serverHello.data(), 9, 11);
    wd_capture_data(&f.capture, flow, WD_DIR_INBOUND, serverHello.data() + 9, serverHello.size() - 9, 11);
    auto results = f.results();
    CHECK(results.front().protocol[0] == WD_PROTOCOL_TLS);
    CHECK(results.front().protocol[1] == WD_PROTOCOL_TLS);
    CHECK(std::string(results.front().tls_sni) == "example.test");
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);

    Bytes dns = {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1};
    flow = f.open(udpPacket(53, dns));
    for (size_t i = 0; i < 40; ++i)
        wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, dns.data(), dns.size(), 11);
    dns[2] = 0x81; dns[3] = 0x80;
    wd_capture_data(&f.capture, flow, WD_DIR_INBOUND, dns.data(), dns.size(), 12);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 13);
    r = f.results().front();
    CHECK(r.protocol[0] == WD_PROTOCOL_DNS && r.protocol[1] == WD_PROTOCOL_DNS);
    CHECK(std::string(r.dns_question) == "example.test");
    CHECK(r.datagrams[0] == 40 && !r.flags[0]);
}

static void destinationTotalsTest() {
    CaptureFixture f;
    auto totals = [&] {
        f.results(); // Wait for the worker before comparing session counters.
        std::vector<wd_destination_summary> rows(wd_analyzer_destinations(f.analyzer, nullptr, 0));
        CHECK(wd_analyzer_destinations(f.analyzer, rows.data(), rows.size()) == rows.size());
        return rows;
    };
    CHECK(totals().empty());
    auto packet = tcpPacket(80, 100, 0, 2);
    auto *flow = f.open(packet);
    auto original = f.events.front().event;
    CHECK(totals().size() == 1 && totals()[0].tcp_connections == 1);
    CHECK(totals()[0].domain[0] == 0);
    wd_capture_packet(&f.capture, packet.data(), packet.size(), 10); // Retransmitted SYN.
    CHECK(totals()[0].tcp_connections == 1);
    std::string http = "GET / HTTP/1.1\r\nHost: EXAMPLE.test\r\n\r\n";
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND,
                    reinterpret_cast<const uint8_t *>(http.data()), http.size(), 11);
    auto rows = totals();
    CHECK(rows.size() == 1 && rows[0].tcp_connections == 1);
    CHECK(std::string(rows[0].domain) == "example.test");
    CHECK(rows[0].protocol == WD_PROTOCOL_HTTP);
    CHECK(rows[0].bytes[0] == http.size() && rows[0].bytes[1] == 0);
    CHECK(rows[0].has_fingerprint && rows[0].app_hop_limit == 63 &&
          rows[0].app_tcp_window == 60000 && rows[0].app_tcp_options_len == 4);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
    CHECK(totals()[0].tcp_connections == 1);

    flow = f.open(tcpPacket(443, 200, 0, 2));
    auto hello = clientHello();
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, hello.data(), hello.size(), 11);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
    rows = totals();
    CHECK(rows.size() == 1 && rows[0].tcp_connections == 2);
    flow = f.open(udpPacket(53, Bytes{0x12,0x34,1,0,0,1,0,0,0,0,0,0,0,0,1,0,1}));
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, (const uint8_t *)"x", 1, 11);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
    rows = totals();
    CHECK(rows.size() == 2); // UDP must not inflate the TCP pie chart.

    // Passive DNS: a plain-TCP flow to an IP seen in a DNS A answer gets the
    // queried name as domain_source 3, but explicit SNI still wins over it.
    Bytes answer = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
        9, 'd', 'n', 's', '-', 'f', 'o', 'u', 'n', 'd', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1,
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 127, 0, 0, 1};
    auto *dnsFlow = f.open(udpPacket(53, {}));
    wd_capture_data(&f.capture, dnsFlow, WD_DIR_INBOUND, answer.data(), answer.size(), 11);
    wd_capture_close(&f.capture, dnsFlow, WD_CLOSE_NORMAL, 12);
    flow = f.open(tcpPacket(8080, 400, 0, 2)); // no SNI/Host at all
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
    rows = totals();
    auto dnsRow = std::find_if(rows.begin(), rows.end(), [](const wd_destination_summary &d) {
        return std::string(d.domain) == "dns-found.test";
    });
    CHECK(dnsRow != rows.end() && dnsRow->tcp_connections == 1 && dnsRow->domain_source == 3);
    flow = f.open(tcpPacket(443, 500, 0, 2));
    auto hello2 = clientHello(); // SNI example.test beats the same passive-DNS name
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, hello2.data(), hello2.size(), 11);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
    rows = totals();
    dnsRow = std::find_if(rows.begin(), rows.end(), [](const wd_destination_summary &d) {
        return std::string(d.domain) == "dns-found.test";
    });
    // The TLS flow's count was moved back out of the DNS-attributed record.
    CHECK(dnsRow != rows.end() && dnsRow->tcp_connections == 1);
    auto exampleRow = std::find_if(rows.begin(), rows.end(), [](const wd_destination_summary &d) {
        return std::string(d.domain) == "example.test";
    });
    CHECK(exampleRow != rows.end() && exampleRow->tcp_connections == 3);
    CHECK(exampleRow->domain_source != 3);
    uint64_t tcp = 0, udp = 0;
    for (const auto &row : rows) { tcp += row.tcp_connections; udp += row.udp_flows; }
    CHECK(tcp == 4 && udp == 2);

    // All destinations survive the 256-flow recent snapshot's eviction.
    for (unsigned i = 0; i < 300; ++i) {
        auto p = tcpPacket(443, i + 300, 0, 2);
        p[16] = 8; p[17] = 8; p[18] = uint8_t(i >> 8); p[19] = uint8_t(i);
        flow = f.open(p);
        CHECK(flow);
        wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
        if (i % 20 == 0) f.results();
    }
    rows = totals();
    CHECK(rows.size() == 303);
    tcp = 0;
    for (const auto &row : rows) tcp += row.tcp_connections;
    CHECK(tcp == 304);
    wd_destination_summary one{};
    CHECK(wd_analyzer_destinations(f.analyzer, &one, 1) == rows.size());
    original.type = WD_FLOW_STATS; // Rehydration must not count the old connection twice.
    wd_analyzer_on_event(f.analyzer, &original);
    rows = totals();
    tcp = 0;
    for (const auto &row : rows) tcp += row.tcp_connections;
    CHECK(tcp == 304);
    CaptureFixture nextSession;
    CHECK(wd_analyzer_destinations(nextSession.analyzer, nullptr, 0) == 0);
}

static void limitsAndLossTest() {
    CaptureFixture f;
    auto *flow = f.open(tcpPacket(443, 100, 0, 2));
    Bytes data(40000, 'x');
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, data.data(), data.size(), 11);
    size_t sampled = 0;
    for (auto &e : f.events) if (e.event.type == WD_TCP_DATA) sampled += e.event.captured;
    CHECK(sampled == WD_CAPTURE_STREAM_BYTES);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
    auto r = f.results().front();
    CHECK(r.flags[0] & WD_FLAG_BUDGET);
    CHECK(!(r.flags[0] & WD_FLAG_GAP));
    CHECK(r.bytes[0] == data.size());

    // The time budget runs from the first payload byte, not from the SYN.
    flow = f.open(tcpPacket(443, 200, 0, 2), 10);
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, data.data(), 10, 20);
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, data.data() + 10, 10, 5020);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 5030);
    r = f.results().front();
    CHECK(r.flags[0] & WD_FLAG_BUDGET);
    CHECK(!(r.flags[0] & WD_FLAG_GAP));

    // A pre-connected socket that starts TLS long after the SYN is still sampled.
    flow = f.open(tcpPacket(443, 250, 0, 2), 10);
    size_t before = f.events.size();
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, data.data(), 16, 900000);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 900001);
    size_t late = 0;
    for (size_t i = before; i < f.events.size(); ++i)
        if (f.events[i].event.type == WD_TCP_DATA) late += f.events[i].event.captured;
    CHECK(late == 16);

    // Deliberately lose a sample at the observer boundary, then stop capture.
    // Final offered counters must still disclose the missing tail.
    flow = f.open(tcpPacket(443, 300, 0, 2));
    f.capture.observer = [](void *ctx, const wd_event *e) {
        if (e->type != WD_TCP_DATA)
            wd_analyzer_on_event(static_cast<CaptureFixture *>(ctx)->analyzer, e);
    };
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, data.data(), data.size(), 11);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
    r = f.results().front();
    CHECK((r.flags[0] & (WD_FLAG_BUDGET | WD_FLAG_GAP)) == (WD_FLAG_BUDGET | WD_FLAG_GAP));

    flow = f.open(udpPacket(53, Bytes(5000)));
    wd_capture_data(&f.capture, flow, WD_DIR_INBOUND, data.data(), 5000, 11);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);
    r = f.results().front();
    CHECK(r.flags[1] & WD_FLAG_TRUNCATED);
    CHECK(r.protocol[1] == WD_PROTOCOL_UNKNOWN);
}

static void malformedAndGapTest() {
    CaptureFixture f;
    auto *flow = f.open(tcpPacket(443, 100, 0, 2));
    Bytes tls = clientHello();
    // A declared record length beyond the capture budget cannot be classified.
    put16(tls, 3, 0xffff);
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, tls.data(), tls.size(), 11);
    CHECK(f.results().front().protocol[0] == WD_PROTOCOL_UNKNOWN);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);

    flow = f.open(udpPacket(53, {}));
    // Cyclic DNS compression pointer must terminate safely, without a domain.
    Bytes dns = {0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1};
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, dns.data(), dns.size(), 11);
    auto r = f.results().front();
    CHECK(r.protocol[0] == WD_PROTOCOL_UNKNOWN && r.dns_question[0] == 0);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 12);

    flow = f.open(tcpPacket(80, 100, 0, 2));
    std::string first = "GET / HTTP/1.1\r\n";
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND,
                    reinterpret_cast<const uint8_t *>(first.data()), first.size(), 11);
    auto observer = f.capture.observer;
    f.capture.observer = [](void *, const wd_event *) {};
    uint8_t lost = 'x';
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, &lost, 1, 12);
    f.capture.observer = observer;
    std::string rest = "Host: must-not-parse.test\r\n\r\n";
    wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND,
                    reinterpret_cast<const uint8_t *>(rest.data()), rest.size(), 13);
    r = f.results().front();
    CHECK(r.flags[0] & WD_FLAG_GAP);
    CHECK(r.protocol[0] == WD_PROTOCOL_UNKNOWN && r.http_host[0] == 0);
    wd_capture_close(&f.capture, flow, WD_CLOSE_NORMAL, 14);

    // A known full flow table must not allocate or overwrite bound identities.
    wd_capture c{};
    c.observer = [](void *, const wd_event *) {};
    wd_flow_key key{};
    key.ipver = 4; key.proto = WD_PROTO_TCP;
    for (size_t i = 0; i < WD_CAPTURE_FLOWS; ++i) {
        key.sport = uint16_t(i);
        CHECK(wd_capture_bind(&c, &key, 10));
    }
    key.sport = WD_CAPTURE_FLOWS;
    CHECK(!wd_capture_bind(&c, &key, 10));
    wd_capture_expire(&c, 70000);
    CHECK(!wd_capture_bind(&c, &key, 70000)); // bound flows cannot be reused by idle cleanup
    wd_capture_close(&c, &c.flows[0], WD_CLOSE_NORMAL, 70000);
    CHECK(wd_capture_bind(&c, &key, 70000));
}

static void parserBudgetTest() {
    /* Inbound data must not consume a parsing slot. Under the old 64-direction
       cache every TLS connection held a server-side slot for the whole capture
       budget, so a busy device ran out and silently lost SNI for new flows. */
    CaptureFixture f;
    uint8_t data = 'x';
    for (unsigned i = 0; i < 200; ++i) {
        auto *flow = f.open(tcpPacket(uint16_t(1000 + i), 100, 0, 2));
        CHECK(flow);
        wd_capture_data(&f.capture, flow, WD_DIR_OUTBOUND, &data, 1, 11);
        wd_capture_data(&f.capture, flow, WD_DIR_INBOUND, &data, 1, 11);
    }
    auto results = f.results();
    CHECK(results.size() == 200);
    for (const auto &r : results) {
        CHECK(!(r.flags[0] & WD_FLAG_CAPACITY));
        CHECK(!(r.flags[1] & WD_FLAG_CAPACITY));
    }
}

struct TunnelFixture {
    std::mutex mutex;
    std::vector<Bytes> output;
    std::vector<SavedEvent> events;
    void *analyzer = wd_analyzer_create();
    wd_tunnel *tunnel;
    TunnelFixture() {
        CHECK(analyzer);
        tunnel = wd_tunnel_create([](void *ctx, const uint8_t *p, size_t len) {
            auto &self = *static_cast<TunnelFixture *>(ctx);
            std::lock_guard<std::mutex> lock(self.mutex);
            self.output.emplace_back(p, p + len);
        }, nullptr, this, [](void *ctx, const wd_event *e) {
            auto &self = *static_cast<TunnelFixture *>(ctx);
            std::lock_guard<std::mutex> lock(self.mutex);
            self.events.emplace_back(*e);
            wd_analyzer_on_event(self.analyzer, e);
        }, this);
        CHECK(tunnel);
    }
    ~TunnelFixture() { stop(); wd_analyzer_destroy(analyzer); }
    void stop() { if (tunnel) wd_tunnel_destroy(tunnel); tunnel = nullptr; }
    void input(const Bytes &p) { wd_tunnel_input(tunnel, p.data(), p.size()); }
    Bytes awaitPacket(const std::function<bool(const Bytes &)> &predicate) {
        Bytes found;
        waitFor([&] {
            std::lock_guard<std::mutex> lock(mutex);
            for (const auto &p : output) if (predicate(p)) { found = p; return true; }
            return false;
        });
        return found;
    }
};

static int listenLocal(int type, uint16_t &port, bool v6) {
    int fd = socket(v6 ? AF_INET6 : AF_INET, type, 0);
    CHECK(fd >= 0);
    if (v6) {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_loopback;
        CHECK(bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
        socklen_t len = sizeof(addr);
        CHECK(getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
        port = ntohs(addr.sin6_port);
    } else {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
        socklen_t len = sizeof(addr);
        CHECK(getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
        port = ntohs(addr.sin_port);
    }
    if (type == SOCK_STREAM) CHECK(listen(fd, 1) == 0);
    return fd;
}

static void readable(int fd) {
    pollfd p{fd, POLLIN, 0};
    CHECK(poll(&p, 1, 5000) > 0);
    CHECK(p.revents & POLLIN);
}

static void forwardingTest(bool v6) {
    uint16_t port;
    int server = listenLocal(SOCK_STREAM, port, v6);
    TunnelFixture t;
    size_t ip = v6 ? 40 : 20;
    t.input(tcpPacket(port, 100, 0, 2, "", v6));
    Bytes synack = t.awaitPacket([&](const Bytes &p) {
        return p.size() >= ip + 20 && (p[ip + 13] & 0x12) == 0x12;
    });
    uint32_t serverSequence = get32(synack.data() + ip + 4);
    t.input(tcpPacket(port, 101, serverSequence + 1, 0x10, "", v6));
    readable(server);
    int peer = accept(server, nullptr, nullptr);
    CHECK(peer >= 0);
    std::string request = "GET / HTTP/1.1\r\nHost: local.test\r\n\r\n";
    size_t split = 12;
    // Deliver the tail first, then the missing head, then a retransmitted head.
    t.input(tcpPacket(port, 101 + split, serverSequence + 1, 0x18, request.substr(split), v6));
    t.input(tcpPacket(port, 101, serverSequence + 1, 0x18, request.substr(0, split), v6));
    t.input(tcpPacket(port, 101, serverSequence + 1, 0x18, request.substr(0, split), v6));
    std::string received;
    while (received.size() < request.size()) {
        readable(peer);
        char b[1024];
        ssize_t n = recv(peer, b, sizeof(b), 0);
        CHECK(n > 0);
        received.append(b, size_t(n));
    }
    CHECK(received == request);
    std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    CHECK(send(peer, response.data(), response.size(), 0) == ssize_t(response.size()));
    std::string appReceived(response.size(), '\0');
    std::vector<bool> covered(response.size());
    waitFor([&] {
        std::lock_guard<std::mutex> lock(t.mutex);
        for (const auto &p : t.output) {
            if (p.size() < ip + 20) continue;
            size_t payload = ip + (p[ip + 12] >> 4) * 4;
            size_t offset = uint32_t(get32(p.data() + ip + 4) - serverSequence - 1);
            for (size_t k = payload; k < p.size() && offset < response.size(); ++k, ++offset) {
                appReceived[offset] = char(p[k]);
                covered[offset] = true;
            }
        }
        return std::all_of(covered.begin(), covered.end(), [](bool present) { return present; });
    });
    CHECK(appReceived == response);
    t.input(tcpPacket(port, 101 + request.size(), serverSequence + 1 + response.size(), 0x14, "", v6));
    waitFor([&] {
        std::lock_guard<std::mutex> lock(t.mutex);
        return std::any_of(t.events.begin(), t.events.end(), [](const SavedEvent &e) {
            return e.event.type == WD_FLOW_CLOSE;
        });
    });
    uint64_t oldId;
    {
        std::lock_guard<std::mutex> lock(t.mutex);
        oldId = t.events.front().event.flow_id;
        std::string out, in;
        bool rawSynBeforeStream = false;
        for (const auto &e : t.events) {
            CHECK(e.event.flow_id == oldId);
            if (e.event.type == WD_PACKET && e.data.size() > ip + 13 && e.data[ip + 13] == 2)
                rawSynBeforeStream = true;
            if (e.event.type == WD_TCP_DATA) {
                CHECK(rawSynBeforeStream);
                (e.event.direction == WD_DIR_OUTBOUND ? out : in).append(e.data.begin(), e.data.end());
            }
            CHECK(e.event.source != WD_SOURCE_APP_PACKET || e.event.direction == WD_DIR_OUTBOUND);
        }
        CHECK(out == request && in == response);
    }
    t.input(tcpPacket(port, 1000, 0, 2, "", v6));
    waitFor([&] {
        std::lock_guard<std::mutex> lock(t.mutex);
        return t.events.back().event.flow_id != oldId;
    });
    t.stop();
    close(peer);
    close(server);

    int udp = listenLocal(SOCK_DGRAM, port, v6);
    TunnelFixture u;
    Bytes query{'d', 'a', 't', 'a'};
    u.input(udpPacket(port, query, v6));
    readable(udp);
    uint8_t b[100];
    sockaddr_storage client{};
    socklen_t size = sizeof(client);
    ssize_t n = recvfrom(udp, b, sizeof(b), 0, reinterpret_cast<sockaddr *>(&client), &size);
    CHECK(n == ssize_t(query.size()) && std::equal(query.begin(), query.end(), b));
    CHECK(sendto(udp, b, size_t(n), 0, reinterpret_cast<sockaddr *>(&client), size) == n);
    Bytes reply = u.awaitPacket([&](const Bytes &p) { return p.size() == ip + 8 + query.size(); });
    CHECK(std::equal(query.begin(), query.end(), reply.begin() + ip + 8));
    uint16_t otherPort;
    int other = listenLocal(SOCK_DGRAM, otherPort, v6);
    u.input(udpPacket(otherPort, query, v6)); // same App source socket, different destination
    readable(other);
    size = sizeof(client);
    n = recvfrom(other, b, sizeof(b), 0, reinterpret_cast<sockaddr *>(&client), &size);
    CHECK(n == ssize_t(query.size()));
    u.stop();
    CHECK(std::count_if(u.events.begin(), u.events.end(), [](const SavedEvent &e) {
        return e.event.type == WD_UDP_DATAGRAM;
    }) == 3);
    uint64_t firstId = u.events.front().event.flow_id;
    for (const auto &e : u.events) {
        if (e.event.flow.dport == port) CHECK(e.event.flow_id == firstId);
        else CHECK(e.event.flow.dport == otherPort && e.event.flow_id != firstId);
    }
    close(other);
    close(udp);
}

/* ---- QUIC Initial inspection ---- */

// AES-GCM encrypt, test-side only: the shipping code only ever opens packets.
static void ghashMulTest(uint8_t acc[16], const uint8_t h[16]) {
    uint8_t v[16], r[16] = {0};
    std::memcpy(v, h, 16);
    for (int bit = 0; bit < 128; ++bit) {
        if (acc[bit / 8] & (0x80 >> (bit % 8)))
            for (int i = 0; i < 16; ++i) r[i] ^= v[i];
        bool lsb = v[15] & 1;
        for (int i = 15; i > 0; --i) v[i] = uint8_t((v[i] >> 1) | (v[i - 1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    std::memcpy(acc, r, 16);
}

static void ghashTest(uint8_t y[16], const uint8_t h[16], const uint8_t *aad, size_t aadLen,
                      const uint8_t *ct, size_t ctLen) {
    uint8_t block[16];
    auto absorb = [&](const uint8_t *p, size_t n) {
        for (size_t i = 0; i < n; i += 16) {
            std::memset(block, 0, 16);
            std::memcpy(block, p + i, n - i < 16 ? n - i : 16);
            for (int k = 0; k < 16; ++k) y[k] ^= block[k];
            ghashMulTest(y, h);
        }
    };
    absorb(aad, aadLen);
    absorb(ct, ctLen);
    std::memset(block, 0, 16);
    uint64_t a = uint64_t(aadLen) * 8, c = uint64_t(ctLen) * 8;
    for (int i = 0; i < 8; ++i) block[i] = uint8_t(a >> (56 - 8 * i));
    for (int i = 0; i < 8; ++i) block[8 + i] = uint8_t(c >> (56 - 8 * i));
    for (int k = 0; k < 16; ++k) y[k] ^= block[k];
    ghashMulTest(y, h);
}

static void gcmEncryptTest(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
                           size_t aadLen, const uint8_t *pt, size_t len, uint8_t *ct,
                           uint8_t tag[16]) {
    linkatlas::Aes128 aes;
    aes.setKey(key);
    uint8_t h[16] = {0}, ek[16], j0[16];
    aes.encryptBlock(h, h);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t ctr[16];
        std::memcpy(ctr, nonce, 12);
        uint32_t v = uint32_t(off / 16) + 2;
        ctr[12] = uint8_t(v >> 24); ctr[13] = uint8_t(v >> 16);
        ctr[14] = uint8_t(v >> 8); ctr[15] = uint8_t(v);
        aes.encryptBlock(ctr, ek);
        size_t take = len - off < 16 ? len - off : 16;
        for (size_t i = 0; i < take; ++i) ct[off + i] = uint8_t(pt[off + i] ^ ek[i]);
    }
    uint8_t y[16] = {0};
    ghashTest(y, h, aad, aadLen, ct, len);
    std::memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    aes.encryptBlock(j0, ek);
    for (int i = 0; i < 16; ++i) tag[i] = uint8_t(y[i] ^ ek[i]);
}

static void quicVarint(Bytes &b, uint64_t v) {
    if (v < 64) b.push_back(uint8_t(v));
    else if (v < 16384) { b.push_back(uint8_t(0x40 | (v >> 8))); b.push_back(uint8_t(v)); }
    else {
        b.push_back(uint8_t(0x80 | (v >> 24))); b.push_back(uint8_t(v >> 16));
        b.push_back(uint8_t(v >> 8)); b.push_back(uint8_t(v));
    }
}

// Raw TLS ClientHello handshake message (no record framing), as QUIC carries it.
static Bytes handshakeClientHello(const std::string &name) {
    Bytes h(4 + 2 + 32 + 1);
    h[0] = 1; h[4] = 3; h[5] = 3;
    h.insert(h.end(), {0, 2, 0x13, 1, 1, 0});
    size_t ext = h.size();
    h.resize(h.size() + 11);
    put16(h, ext, uint16_t(9 + name.size()));
    put16(h, ext + 2, 0);
    put16(h, ext + 4, uint16_t(5 + name.size()));
    put16(h, ext + 6, uint16_t(3 + name.size()));
    h[ext + 8] = 0;
    put16(h, ext + 9, uint16_t(name.size()));
    h.insert(h.end(), name.begin(), name.end());
    h[1] = uint8_t((h.size() - 4) >> 16);
    put16(h, 2, uint16_t(h.size() - 4));
    return h;
}

// Builds client Initial packets carrying the ClientHello, split every `chunk` bytes.
static std::vector<Bytes> buildQuicInitials(const std::string &sni, const Bytes &dcid, size_t chunk) {
    static const uint8_t SaltV1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                       0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
    Bytes hello = handshakeClientHello(sni);
    uint8_t secret[32], client[32], key[16], iv[12], hp[16];
    linkatlas::hkdfExtract(SaltV1, 20, dcid.data(), dcid.size(), secret);
    linkatlas::hkdfExpandLabel(secret, "client in", nullptr, 0, client, 32);
    linkatlas::hkdfExpandLabel(client, "quic key", nullptr, 0, key, 16);
    linkatlas::hkdfExpandLabel(client, "quic iv", nullptr, 0, iv, 12);
    linkatlas::hkdfExpandLabel(client, "quic hp", nullptr, 0, hp, 16);

    std::vector<Bytes> out;
    uint64_t pn = 1;
    for (size_t off = 0; off < hello.size(); off += chunk) {
        size_t n = std::min(chunk, hello.size() - off);
        Bytes payload;
        quicVarint(payload, 0x06);
        quicVarint(payload, off);
        quicVarint(payload, n);
        payload.insert(payload.end(), hello.begin() + off, hello.begin() + off + n);

        Bytes header;
        const size_t pnLen = 4;
        header.push_back(uint8_t(0xc0 | 0x03));
        header.insert(header.end(), {0, 0, 0, 1});
        header.push_back(uint8_t(dcid.size()));
        header.insert(header.end(), dcid.begin(), dcid.end());
        header.push_back(0);
        quicVarint(header, 0);
        quicVarint(header, payload.size() + pnLen + 16);
        const size_t pnOffset = header.size();
        for (int i = 3; i >= 0; --i) header.push_back(uint8_t(pn >> (8 * i)));

        uint8_t nonce[12];
        std::memcpy(nonce, iv, 12);
        for (int i = 0; i < 4; ++i) nonce[11 - i] ^= uint8_t(pn >> (8 * i));
        Bytes ciphertext(payload.size());
        uint8_t tag[16];
        gcmEncryptTest(key, nonce, header.data(), header.size(), payload.data(), payload.size(),
                       ciphertext.data(), tag);

        Bytes packet = header;
        packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
        packet.insert(packet.end(), tag, tag + 16);
        uint8_t mask[16];
        {
            linkatlas::Aes128 aes;
            aes.setKey(hp);
            aes.encryptBlock(packet.data() + pnOffset + 4, mask);
        }
        packet[0] ^= uint8_t(mask[0] & 0x0f);
        for (int i = 0; i < 4; ++i) packet[pnOffset + i] ^= uint8_t(mask[1 + i]);
        out.push_back(std::move(packet));
        ++pn;
    }
    return out;
}

static void quicTest() {
    // RFC 9001 A.1 key derivation.
    static const uint8_t SaltV1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                       0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
    Bytes dcid = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    uint8_t secret[32], client[32], key[16];
    linkatlas::hkdfExtract(SaltV1, 20, dcid.data(), dcid.size(), secret);
    const uint8_t expectedSecret[32] = {0x7d,0xb5,0xdf,0x06,0xe7,0xa6,0x9e,0x43,0x24,0x96,0xad,0xed,0xb0,0x08,0x51,0x92,
                                        0x35,0x95,0x22,0x15,0x96,0xae,0x2a,0xe9,0xfb,0x81,0x15,0xc1,0xe9,0xed,0x0a,0x44};
    CHECK(!std::memcmp(secret, expectedSecret, 32));
    linkatlas::hkdfExpandLabel(secret, "client in", nullptr, 0, client, 32);
    linkatlas::hkdfExpandLabel(client, "quic key", nullptr, 0, key, 16);
    const uint8_t expectedKey[16] = {0x1f,0x36,0x96,0x13,0xdd,0x76,0xd5,0x46,
                                     0x77,0x30,0xef,0xcb,0xe3,0xb1,0xa2,0x2d};
    CHECK(!std::memcmp(key, expectedKey, 16));

    // One Initial packet.
    {
        auto packets = buildQuicInitials("video-cdn.example.test", {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88}, 512);
        linkatlas::QuicCryptoStream stream;
        char sni[256]{};
        bool got = false;
        for (const auto &p : packets) got |= linkatlas::quicClientHelloSni(p.data(), p.size(), stream, sni);
        CHECK(got && std::string(sni) == "video-cdn.example.test");
    }
    // Split across packets, delivered out of order.
    {
        auto packets = buildQuicInitials("split.example.test", {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11}, 23);
        CHECK(packets.size() > 1);
        linkatlas::QuicCryptoStream stream;
        char sni[256]{};
        bool got = false;
        for (size_t i = packets.size(); i-- > 0;)
            got |= linkatlas::quicClientHelloSni(packets[i].data(), packets[i].size(), stream, sni);
        CHECK(got && std::string(sni) == "split.example.test");
    }
    // Tampered ciphertext must fail AEAD and yield nothing.
    {
        auto packets = buildQuicInitials("x.example.test", {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}, 512);
        Bytes packet = packets[0];
        packet[packet.size() - 20] ^= 0x01;
        linkatlas::QuicCryptoStream stream;
        char sni[256]{};
        CHECK(!linkatlas::quicClientHelloSni(packet.data(), packet.size(), stream, sni));
    }
    // Short-header packets are not inspectable and must not be parsed.
    {
        Bytes shortHeader(64, 0x40);
        linkatlas::QuicCryptoStream stream;
        char sni[256]{};
        CHECK(!linkatlas::quicClientHelloSni(shortHeader.data(), shortHeader.size(), stream, sni));
    }
    // The analyzer must report QUIC as its own protocol, not as TLS over TCP.
    {
        void *analyzer = wd_analyzer_create();
        CHECK(analyzer);
        auto packets = buildQuicInitials("quic.example.test", {1,2,3,4,5,6,7,8}, 512);
        wd_event open{};
        open.flow_id = 1;
        open.flow.ipver = 4;
        open.flow.proto = WD_PROTO_UDP;
        open.flow.sport = 40000;
        open.flow.dport = 443;
        open.flow.src[0] = 10; open.flow.src[3] = 2;
        open.flow.dst[0] = 111; open.flow.dst[1] = 132; open.flow.dst[2] = 33; open.flow.dst[3] = 79;
        open.type = WD_FLOW_OPEN;
        open.source = WD_SOURCE_LIFECYCLE;
        open.timestamp_ms = 1000;
        wd_analyzer_on_event(analyzer, &open);
        for (size_t i = 0; i < packets.size(); ++i) {
            wd_event d = open;
            d.type = WD_UDP_DATAGRAM;
            d.source = WD_SOURCE_APP_DATAGRAM;
            d.direction = WD_DIR_OUTBOUND;
            d.offset = i;
            d.timestamp_ms = 1000 + i;
            d.data = packets[i].data();
            d.length = d.captured = packets[i].size();
            wd_analyzer_on_event(analyzer, &d);
        }
        wd_event close = open;
        close.type = WD_FLOW_CLOSE;
        close.timestamp_ms = 2000;
        wd_analyzer_on_event(analyzer, &close);
        waitFor([&] {
            wd_analyzer_stats stats{};
            wd_analyzer_get_stats(analyzer, &stats);
            return stats.enqueued == stats.processed;
        });
        std::vector<wd_destination_summary> rows(wd_analyzer_destinations(analyzer, nullptr, 0));
        CHECK(wd_analyzer_destinations(analyzer, rows.data(), rows.size()) == rows.size());
        CHECK(rows.size() == 1);
        CHECK(rows[0].protocol == WD_PROTOCOL_QUIC);
        CHECK(std::string(rows[0].domain) == "quic.example.test");
        wd_analyzer_destroy(analyzer);
    }
}

/* A passive-DNS name outlives its TTL: an already-named flow keeps the name, and a
   connection started later in the session is still resolved from the cache. */
static void passiveDnsRetentionTest() {
    CaptureFixture f;
    auto rows = [&] {
        f.results();
        std::vector<wd_destination_summary> out(wd_analyzer_destinations(f.analyzer, nullptr, 0));
        CHECK(wd_analyzer_destinations(f.analyzer, out.data(), out.size()) == out.size());
        return out;
    };
    // A record for 127.0.0.1 with a 1 second TTL, observed at t=1000ms.
    Bytes answer = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
        3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1,
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1};
    auto *dns = f.open(udpPacket(53, {}), 1000);
    CHECK(dns);
    wd_capture_data(&f.capture, dns, WD_DIR_INBOUND, answer.data(), answer.size(), 1000);
    wd_capture_close(&f.capture, dns, WD_CLOSE_NORMAL, 1001);

    // First connection, attributed only by passive DNS.
    auto *first = f.open(tcpPacket(8080, 400, 0, 2), 2000);
    CHECK(first);
    auto named = [&](const std::vector<wd_destination_summary> &r) {
        return std::find_if(r.begin(), r.end(), [](const wd_destination_summary &d) {
            return std::string(d.domain) == "cdn.example.test";
        });
    };
    auto r = rows();
    CHECK(named(r) != r.end() && named(r)->domain_source == 3);

    // Long transfer reported after the TTL lapsed: the name must not be revoked,
    // and the byte total must stay on the named row.
    wd_capture_data(&f.capture, first, WD_DIR_INBOUND, reinterpret_cast<const uint8_t *>("x"), 1, 5000);
    wd_capture_expire(&f.capture, 5000);
    r = rows();
    auto row = named(r);
    CHECK(row != r.end() && row->tcp_connections == 1);
    CHECK(row->bytes[1] > 0);

    // A connection started well past the TTL is still resolved from the cache.
    auto *later = f.open(tcpPacket(8081, 900, 0, 2), 500000);
    CHECK(later);
    wd_capture_close(&f.capture, later, WD_CLOSE_NORMAL, 500001);
    r = rows();
    row = named(r);
    CHECK(row != r.end() && row->tcp_connections == 2);
}

int main() {
    queueTest();
    packetAndIdentityTest();
    protocolTest();
    destinationTotalsTest();
    passiveDnsRetentionTest();
    quicTest();
    limitsAndLossTest();
    malformedAndGapTest();
    parserBudgetTest();
    forwardingTest(false);
    forwardingTest(true);
    std::puts("PASS queue, identity, HTTP/TLS/DNS/QUIC, passive-DNS retention, limits/gaps, forwarding");
}
