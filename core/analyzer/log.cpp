#include "log.h"

#include <cstdarg>
#include <cstdio>

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace linkatlas {

/* Diagnostics are a debug-build feature: a shipping build must never write
   observed domains to logcat or stderr. Enable with -DLINKATLAS_DPI_LOG=1. */
#ifndef LINKATLAS_DPI_LOG
#define LINKATLAS_DPI_LOG 0
#endif

void logf(const char *fmt, ...) {
#if !LINKATLAS_DPI_LOG
    (void)fmt;
#else
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
#if defined(__ANDROID__)
    __android_log_write(ANDROID_LOG_INFO, "LinkAtlasDpi", buf);
#else
    std::fprintf(stderr, "[dpi] %s\n", buf);
#endif
#endif  // LINKATLAS_DPI_LOG
}

}  // namespace linkatlas
