/* Parsers shared between the stream analyzer and the QUIC Initial inspector. */
#ifndef LINKATLAS_PROTOCOLS_H
#define LINKATLAS_PROTOCOLS_H

#include <cstdint>
#include <vector>

namespace linkatlas {

/* Input is one complete TLS handshake message (record framing already removed).
   Returns true when the message parsed; sni is filled when a client hello carried it. */
bool tlsClientHelloSni(const std::vector<uint8_t> &handshake, char *sni);

}  // namespace linkatlas

#endif
