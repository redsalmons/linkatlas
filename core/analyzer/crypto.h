/* Minimal SHA-256 / HMAC / HKDF / AES-128 primitives needed to peel QUIC Initial packets.
   QUIC Initial keys derive from the plaintext Destination Connection ID, so no secret is
   involved; only the AEAD and header-protection algorithms are required. */
#ifndef LINKATLAS_CRYPTO_H
#define LINKATLAS_CRYPTO_H

#include <cstddef>
#include <cstdint>

namespace linkatlas {

void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t dataLen,
                uint8_t out[32]);
void hkdfExtract(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen,
                 uint8_t out[32]);
/* RFC 8446 HKDF-Expand-Label with SHA-256 ("tls13 " prefix applied internally). */
void hkdfExpandLabel(const uint8_t secret[32], const char *label, const uint8_t *context,
                     size_t contextLen, uint8_t *out, size_t outLen);

class Aes128 {
public:
    void setKey(const uint8_t key[16]);
    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const;
private:
    uint8_t roundKeys_[176];
};

/* AES-128-GCM open with tag verification. Returns false on authentication failure. */
bool aes128GcmDecrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
                      size_t aadLen, const uint8_t *ct, size_t ctLen,
                      const uint8_t tag[16], uint8_t *out);

}  // namespace linkatlas

#endif
