/* Minimal diagnostic logging for the analyzer.
   Android routes to logcat (tag LinkAtlasDpi); other platforms to stderr. */
#ifndef LINKATLAS_LOG_H
#define LINKATLAS_LOG_H

namespace linkatlas {

void logf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

}  // namespace linkatlas

#endif
