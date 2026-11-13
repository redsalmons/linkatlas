/* QUIC Initial packet inspection.
   Initial packets are protected with keys derived from the plaintext Destination
   Connection ID (RFC 9001 5.2), so the client's TLS ClientHello - and therefore
   the SNI - can be recovered without any secret. Only Initial packets are opened;
   Handshake and 1-RTT packets stay opaque. */
#ifndef LINKATLAS_QUIC_H
#define LINKATLAS_QUIC_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace linkatlas {

/* Reassembles one direction's CRYPTO stream across Initial packets. */
struct QuicCryptoStream {
    std::vector<uint8_t> bytes;  /* contiguous prefix starting at offset 0 */
    std::vector<uint8_t> have;   /* per-byte presence, same length as bytes */
    size_t contiguous = 0;
    bool done = false;           /* parsed, given up, or oversized */
};

/* Feeds one datagram. Returns true when a ClientHello was completed and sni filled. */
bool quicClientHelloSni(const uint8_t *data, size_t len, QuicCryptoStream &stream, char *sni);

}  // namespace linkatlas

#endif
