#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <string>
#include <unordered_map>
#include <vector>
#include "linkatlas/analyzer.h"
#include "quic.h"

namespace linkatlas {

/* SPSC bounded copy queue, independently usable without a running worker.
   peek() stays valid until pop(); no producer allocation or consumer locks. */
class ObservationQueue {
public:
    static constexpr size_t Size = 2048, ControlReserve = 32;
    ObservationQueue();
    bool push(const wd_event &event);
    const wd_event *peek();
    void pop();
private:
    struct Slot {
        wd_event event{};
        std::array<uint8_t, WD_CAPTURE_CHUNK> data{};
    };
    std::unique_ptr<Slot[]> slots_;
    alignas(64) std::atomic<uint64_t> head_{0};
    alignas(64) std::atomic<uint64_t> tail_{0};
};

class Analyzer {
public:
    Analyzer();
    ~Analyzer();
    void onEvent(const wd_event &event);
    size_t snapshot(wd_flow_summary *out, size_t capacity);
    /* Drops every retained flow, destination total and passive-DNS entry.
       Safe to call while the worker runs; queued events may re-appear once. */
    void reset();
    void stats(wd_analyzer_stats &out);
    size_t destinations(wd_destination_summary *out, size_t capacity);

private:
    static constexpr size_t MaxFlows = 256, MaxParsingDirections = 256;
    /* Only the handshake is retained: a few KiB, never the whole sampling budget. */
    static constexpr size_t MaxHandshakeBytes = 16384;
    struct Direction {
        uint64_t next = 0;
        bool stopped = false;
        bool allocated = false;
        std::vector<uint8_t> prefix;
        std::vector<uint8_t> handshake;
        size_t tls_cursor = 0;
        bool tls = false;
    };
    struct Flow {
        wd_flow_summary result{};
        Direction directions[2];
        uint64_t received[2]{};
        uint64_t next_packet = 0;
        uint64_t touched = 0; // worker's monotonic time, also when no traffic arrives
        std::string destination_key;
        uint64_t attributed_bytes[2]{}; // already moved into destination_key's totals
        // Best attribution ever made for this flow. Passive-DNS entries expire
        // by TTL, but a long-lived transfer must not lose the name it already
        // earned, so this is never downgraded; SNI / HTTP Host still upgrade it.
        std::string sticky_domain;
        uint8_t sticky_source = 0;
        QuicCryptoStream quicOut;  /* client-side QUIC Initial CRYPTO reassembly */
    };
    void run();
    void process(const wd_event &event);
    void parseStream(Flow &flow, const wd_event &event);
    void stopParsing(Direction &direction);
    struct DnsEntry {
        std::string name;
        uint64_t resolved_ms, expiry_ms, retain_ms;
    };
    void expire(uint64_t now);
    void recordDestination(Flow &flow, const wd_event &event);
    void parseDnsAnswers(const uint8_t *data, size_t len, uint64_t now);
    void recordDns(uint8_t ver, const uint8_t *addr, size_t addrLen,
                   const std::string &name, uint32_t ttl, uint64_t now);
    std::string dnsLookup(uint8_t ver, const uint8_t *dst, uint64_t now);
    ObservationQueue queue_;
    std::atomic<bool> stopping_{false};
    std::atomic<uint64_t> dropped_data_{0}, dropped_control_{0}, enqueued_{0};
    std::mutex wake_mutex_, results_mutex_;
    std::condition_variable wake_;
    std::unordered_map<uint64_t, Flow> flows_;
    std::unordered_map<std::string, wd_destination_summary> destinations_;
    std::unordered_map<std::string, DnsEntry> dns_map_;
    size_t parsing_directions_ = 0;
    wd_analyzer_stats stats_{};
    std::thread worker_;
};

}  // namespace linkatlas
