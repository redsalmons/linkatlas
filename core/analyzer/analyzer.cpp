#include "analyzer.h"

#include "watchdog/analyzer.h"

namespace watchdog {

void Analyzer::onPacket(const uint8_t *packet, size_t len, wd_direction dir) {
    // Analysis to be defined once the captured data has been evaluated.
    (void)packet;
    (void)len;
    (void)dir;
}

}  // namespace watchdog

extern "C" {

void *wd_analyzer_create(void) { return new watchdog::Analyzer(); }

void wd_analyzer_destroy(void *analyzer) { delete static_cast<watchdog::Analyzer *>(analyzer); }

void wd_analyzer_on_packet(void *analyzer, const uint8_t *packet, size_t len, wd_direction dir) {
    static_cast<watchdog::Analyzer *>(analyzer)->onPacket(packet, len, dir);
}

}
