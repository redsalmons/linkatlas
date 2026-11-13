#include "crypto.h"

#include <cstring>

namespace linkatlas {
namespace {

constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256Block(uint32_t h[8], const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
               (uint32_t(p[i * 4 + 2]) << 8) | p[i * 4 + 3];
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = k + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

void sha256Init(uint32_t h[8]) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::memcpy(h, iv, sizeof(iv));
}

void sha256Update(uint32_t h[8], const uint8_t *data, size_t len) {
    for (size_t i = 0; i + 64 <= len; i += 64) sha256Block(h, data + i);
}

void sha256Finish(uint32_t h[8], const uint8_t *tail, size_t tailLen, uint64_t totalBits) {
    uint8_t block[128];
    std::memset(block, 0, sizeof(block));
    std::memcpy(block, tail, tailLen);
    block[tailLen] = 0x80;
    size_t used = tailLen + 1 <= 56 ? 64 : 128;
    for (int i = 0; i < 8; ++i) block[used - 1 - i] = uint8_t(totalBits >> (8 * i));
    sha256Block(h, block);
    if (used == 128) sha256Block(h, block + 64);
}

void store32(uint8_t *p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}

/* --- AES --- */
const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

uint8_t xtime(uint8_t x) { return uint8_t((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

/* acc = acc * h in GF(2^128); the accumulator supplies the multiplier bits and H
   is the shifted multiplicand, per NIST SP 800-38D Algorithm 1. */
void ghashMul(uint8_t acc[16], const uint8_t h[16]) {
    uint8_t v[16];
    std::memcpy(v, h, 16);
    uint8_t r[16] = {0};
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

void ghash(uint8_t y[16], const uint8_t h[16], const uint8_t *aad, size_t aadLen,
           const uint8_t *ct, size_t ctLen) {
    uint8_t block[16];
    auto absorb = [&](const uint8_t *p, size_t n) {
        for (size_t i = 0; i < n; i += 16) {
            std::memset(block, 0, 16);
            size_t take = n - i < 16 ? n - i : 16;
            std::memcpy(block, p + i, take);
            for (int k = 0; k < 16; ++k) y[k] ^= block[k];
            ghashMul(y, h);
        }
    };
    absorb(aad, aadLen);
    absorb(ct, ctLen);
    std::memset(block, 0, 16);
    uint64_t a = uint64_t(aadLen) * 8, c = uint64_t(ctLen) * 8;
    for (int i = 0; i < 8; ++i) block[i] = uint8_t(a >> (56 - 8 * i));
    for (int i = 0; i < 8; ++i) block[8 + i] = uint8_t(c >> (56 - 8 * i));
    for (int k = 0; k < 16; ++k) y[k] ^= block[k];
    ghashMul(y, h);
}

}  // namespace

void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8];
    sha256Init(h);
    size_t whole = len / 64 * 64;
    sha256Update(h, data, whole);
    sha256Finish(h, data + whole, len - whole, uint64_t(len) * 8);
    for (int i = 0; i < 8; ++i) store32(out + i * 4, h[i]);
}

void hmacSha256(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t dataLen,
                uint8_t out[32]) {
    uint8_t block[64];
    std::memset(block, 0, sizeof(block));
    if (keyLen > 64) sha256(key, keyLen, block);
    else std::memcpy(block, key, keyLen);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = block[i] ^ 0x36; opad[i] = block[i] ^ 0x5c; }
    uint8_t inner[32];
    {
        uint32_t h[8];
        sha256Init(h);
        sha256Update(h, ipad, 64);
        size_t whole = dataLen / 64 * 64;
        sha256Update(h, data, whole);
        sha256Finish(h, data + whole, dataLen - whole, uint64_t(64 + dataLen) * 8);
        for (int i = 0; i < 8; ++i) store32(inner + i * 4, h[i]);
    }
    uint32_t h[8];
    sha256Init(h);
    sha256Update(h, opad, 64);
    sha256Finish(h, inner, 32, uint64_t(64 + 32) * 8);
    for (int i = 0; i < 8; ++i) store32(out + i * 4, h[i]);
}

void hkdfExtract(const uint8_t *salt, size_t saltLen, const uint8_t *ikm, size_t ikmLen,
                 uint8_t out[32]) {
    hmacSha256(salt, saltLen, ikm, ikmLen, out);
}

void hkdfExpandLabel(const uint8_t secret[32], const char *label, const uint8_t *context,
                     size_t contextLen, uint8_t *out, size_t outLen) {
    uint8_t info[2 + 1 + 255 + 1 + 255];
    size_t labelLen = std::strlen(label), pos = 0;
    info[pos++] = uint8_t(outLen >> 8);
    info[pos++] = uint8_t(outLen);
    info[pos++] = uint8_t(6 + labelLen);
    std::memcpy(info + pos, "tls13 ", 6); pos += 6;
    std::memcpy(info + pos, label, labelLen); pos += labelLen;
    info[pos++] = uint8_t(contextLen);
    if (contextLen) { std::memcpy(info + pos, context, contextLen); pos += contextLen; }

    uint8_t t[32];
    size_t produced = 0;
    uint8_t counter = 1;
    while (produced < outLen) {
        uint8_t buf[64 + 32 + sizeof(info)];
        size_t n = 0;
        if (counter > 1) { std::memcpy(buf, t, 32); n = 32; }
        std::memcpy(buf + n, info, pos); n += pos;
        buf[n++] = counter;
        hmacSha256(secret, 32, buf, n, t);
        size_t take = outLen - produced < 32 ? outLen - produced : 32;
        std::memcpy(out + produced, t, take);
        produced += take;
        ++counter;
    }
}

void Aes128::setKey(const uint8_t key[16]) {
    std::memcpy(roundKeys_, key, 16);
    uint8_t rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4] = {roundKeys_[i - 4], roundKeys_[i - 3], roundKeys_[i - 2], roundKeys_[i - 1]};
        if (i % 16 == 0) {
            uint8_t tmp = t[0];
            t[0] = uint8_t(SBOX[t[1]] ^ rcon); t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]]; t[3] = SBOX[tmp];
            rcon = xtime(rcon);
        }
        for (int k = 0; k < 4; ++k) roundKeys_[i + k] = uint8_t(roundKeys_[i - 16 + k] ^ t[k]);
    }
}

void Aes128::encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
    uint8_t s[16];
    std::memcpy(s, in, 16);
    for (int k = 0; k < 16; ++k) s[k] ^= roundKeys_[k];
    for (int round = 1; round <= 10; ++round) {
        uint8_t t[16];
        for (int k = 0; k < 16; ++k) t[k] = SBOX[s[k]];
        uint8_t r[16];
        for (int row = 0; row < 4; ++row)
            for (int col = 0; col < 4; ++col)
                r[row + 4 * col] = t[row + 4 * ((col + row) & 3)];
        if (round != 10) {
            for (int col = 0; col < 4; ++col) {
                uint8_t *c = r + 4 * col;
                uint8_t a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];
                uint8_t all = uint8_t(a0 ^ a1 ^ a2 ^ a3);
                c[0] = uint8_t(a0 ^ all ^ xtime(uint8_t(a0 ^ a1)));
                c[1] = uint8_t(a1 ^ all ^ xtime(uint8_t(a1 ^ a2)));
                c[2] = uint8_t(a2 ^ all ^ xtime(uint8_t(a2 ^ a3)));
                c[3] = uint8_t(a3 ^ all ^ xtime(uint8_t(a3 ^ a0)));
            }
        }
        for (int k = 0; k < 16; ++k) s[k] = uint8_t(r[k] ^ roundKeys_[round * 16 + k]);
    }
    std::memcpy(out, s, 16);
}

bool aes128GcmDecrypt(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
                      size_t aadLen, const uint8_t *ct, size_t ctLen,
                      const uint8_t tag[16], uint8_t *out) {
    Aes128 aes;
    aes.setKey(key);
    uint8_t h[16] = {0}, hj[16];
    aes.encryptBlock(h, h);

    uint8_t y[16] = {0};
    ghash(y, h, aad, aadLen, ct, ctLen);

    uint8_t j0[16];
    std::memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    uint8_t ek[16];
    aes.encryptBlock(j0, ek);
    for (int i = 0; i < 16; ++i) y[i] ^= ek[i];
    if (std::memcmp(y, tag, 16) != 0) return false;

    for (size_t off = 0; off < ctLen; off += 16) {
        uint8_t ctr[16];
        std::memcpy(ctr, nonce, 12);
        uint32_t v = uint32_t(off / 16) + 2;
        ctr[12] = uint8_t(v >> 24); ctr[13] = uint8_t(v >> 16);
        ctr[14] = uint8_t(v >> 8); ctr[15] = uint8_t(v);
        aes.encryptBlock(ctr, hj);
        size_t take = ctLen - off < 16 ? ctLen - off : 16;
        for (size_t i = 0; i < take; ++i) out[off + i] = uint8_t(ct[off + i] ^ hj[i]);
    }
    return true;
}

}  // namespace linkatlas
