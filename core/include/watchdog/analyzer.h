/* C entry points of the C++ packet analyzer, usable from Swift, JNI and C. */
#ifndef WATCHDOG_ANALYZER_H
#define WATCHDOG_ANALYZER_H

#include "watchdog/tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

void *wd_analyzer_create(void);
void wd_analyzer_destroy(void *analyzer);
/* Matches wd_packet_fn; pass it to wd_tunnel_create with the analyzer as hook_ctx. */
void wd_analyzer_on_packet(void *analyzer, const uint8_t *packet, size_t len, wd_direction dir);

#ifdef __cplusplus
}
#endif

#endif
