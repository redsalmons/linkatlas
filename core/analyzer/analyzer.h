#pragma once

#include <cstddef>
#include <cstdint>

#include "watchdog/tunnel.h"

namespace watchdog {

class Analyzer {
public:
    // Called on the tunnel thread for every captured packet; must return quickly.
    void onPacket(const uint8_t *packet, size_t len, wd_direction dir);
};

}  // namespace watchdog
