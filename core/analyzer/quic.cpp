#include "quic.h"

#include "crypto.h"
#include "protocols.h"

#include <cstring>

namespace linkatlas {
namespace {

constexpr uint32_t Version1 = 0x00000001, Version2 = 0x6b3343cf, VersionDraft29 = 0xff00001d;
constexpr size_t MaxHandshake = 16384;  /* a ClientHello never needs more */

/* RFC 9001 5.2 (v1), RFC 9369 3.3 (v2) and draft-ietf-quic-tls-29+. */
const uint8_t SaltV1[20] = {0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
                            0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
const uint8_t SaltV2[20] = {0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,
                            0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9};
const uint8_t SaltDraft29[20] = {0xaf,0xbf,0xec,0x28,0x99,0x93,0xd2,0x4c,0x9e,0x97,
                                 0x86,0xf1,0x9c,0x61,0x11,0xe0,0x43,0x90,0xa8,0x99};
const uint8_t *saltFor(uint32_t version) {
    if (version == Version1) return SaltV1;
    if (version == Version2) return SaltV2;
    if (version == VersionDraft29) return SaltDraft29;
    return nullptr;
}

/* Initial is packet type 0 in v1/draft, but 1 in v2 (RFC 9369 3.2). */
bool isInitial(uint32_t version, uint8_t first) {
    unsigned type = (first >> 4) & 0x3;
    return version == Version2 ? type == 1 : type == 0;
}

uint32_t be32(const uint8_t *p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
size_t be24(const uint8_t *p) { return (size_t(p[0]) << 16) | (size_t(p[1]) << 8) | p[2]; }

bool varint(const uint8_t *p, size_t len, size_t &pos, uint64_t &out) {
    if (pos >= len) return false;
    size_t n = size_t(1) << (p[pos] >> 6);
    if (pos + n > len) return false;
    uint64_t v = p[pos] & 0x3f;
    for (size_t i = 1; i < n; ++i) v = (v << 8) | p[pos + i];
    pos += n;
    out = v;
    return true;
}

struct PacketKeys {
    uint8_t key[16], iv[12], hp[16];
};

bool deriveKeys(uint32_t version, const uint8_t *dcid, size_t dcidLen, PacketKeys &out) {
    const uint8_t *salt = saltFor(version);
    if (!salt || !dcidLen || dcidLen > 20) return false;
    uint8_t secret[32];
    hkdfExtract(salt, 20, dcid, dcidLen, secret);
    uint8_t clientSecret[32];
    hkdfExpandLabel(secret, "client in", nullptr, 0, clientSecret, 32);
    hkdfExpandLabel(clientSecret, "quic key", nullptr, 0, out.key, 16);
    hkdfExpandLabel(clientSecret, "quic iv", nullptr, 0, out.iv, 12);
    hkdfExpandLabel(clientSecret, "quic hp", nullptr, 0, out.hp, 16);
    return true;
}

/* Release the reassembly buffers as soon as the answer is known: the only thing
   that matters is the ClientHello, not the connection that carried it. */
void releaseStream(QuicCryptoStream &s) {
    s.done = true;
    std::vector<uint8_t>().swap(s.bytes);
    std::vector<uint8_t>().swap(s.have);
    s.contiguous = 0;
}

void insertCrypto(QuicCryptoStream &s, uint64_t offset, const uint8_t *data, size_t n) {
    if (s.done || n == 0) return;
    if (offset + n > MaxHandshake) { releaseStream(s); return; }
    if (s.bytes.size() < offset + n) {
        s.bytes.resize(size_t(offset + n), 0);
        s.have.resize(size_t(offset + n), 0);
    }
    std::memcpy(s.bytes.data() + offset, data, n);
    std::memset(s.have.data() + offset, 1, n);
    while (s.contiguous < s.bytes.size() && s.have[s.contiguous]) ++s.contiguous;
}

}  // namespace

bool quicClientHelloSni(const uint8_t *data, size_t len, QuicCryptoStream &stream, char *sni) {
    if (stream.done || len < 7) return false;
    if (!(data[0] & 0x80)) return false;  /* short header: not inspectable */
    uint32_t version = be32(data + 1);
    if (!saltFor(version) || !isInitial(version, data[0])) return false;

    size_t pos = 5;
    size_t dcidLen = data[pos++];
    if (dcidLen > 20 || pos + dcidLen > len) return false;
    const uint8_t *dcid = data + pos;
    pos += dcidLen;
    if (pos >= len) return false;
    size_t scidLen = data[pos++];
    if (scidLen > 20 || pos + scidLen > len) return false;
    pos += scidLen;

    uint64_t tokenLen = 0, bodyLen = 0;
    if (!varint(data, len, pos, tokenLen)) return false;
    if (tokenLen > len - pos) return false;
    pos += size_t(tokenLen);
    if (!varint(data, len, pos, bodyLen)) return false;

    size_t pnOffset = pos;
    if (pnOffset + 4 + 16 > len) return false;

    PacketKeys keys{};
    if (!deriveKeys(version, dcid, dcidLen, keys)) return false;

    uint8_t mask[16];
    {
        Aes128 hp;
        hp.setKey(keys.hp);
        hp.encryptBlock(data + pnOffset + 4, mask);
    }
    uint8_t first = uint8_t(data[0] ^ (mask[0] & 0x0f));
    size_t pnLen = size_t(first & 0x03) + 1;
    if (bodyLen < pnLen + 16) return false;
    size_t headerLen = pnOffset + pnLen;
    if (headerLen + (bodyLen - pnLen) > len) return false;

    uint8_t header[128];
    if (headerLen > sizeof(header)) return false;
    std::memcpy(header, data, headerLen);
    header[0] = first;
    uint64_t pn = 0;
    for (size_t i = 0; i < pnLen; ++i) {
        header[pnOffset + i] = uint8_t(data[pnOffset + i] ^ mask[1 + i]);
        pn = (pn << 8) | header[pnOffset + i];
    }

    size_t ctLen = size_t(bodyLen) - pnLen - 16;
    const uint8_t *ct = data + headerLen;
    const uint8_t *tag = ct + ctLen;

    uint8_t nonce[12];
    std::memcpy(nonce, keys.iv, 12);
    for (size_t i = 0; i < 8 && i < pnLen; ++i)
        nonce[11 - i] ^= uint8_t(pn >> (8 * i));

    uint8_t plain[4096];
    if (ctLen > sizeof(plain)) return false;
    if (!aes128GcmDecrypt(keys.key, nonce, header, headerLen, ct, ctLen, tag, plain)) return false;

    /* Walk frames; only CRYPTO carries the ClientHello. */
    size_t at = 0;
    while (at < ctLen) {
        uint64_t type = 0;
        if (!varint(plain, ctLen, at, type)) break;
        if (type == 0x00) continue;                    /* PADDING */
        if (type == 0x01) continue;                    /* PING */
        if (type == 0x02 || type == 0x03) {            /* ACK */
            uint64_t largest = 0, delay = 0, rangeCount = 0, firstRange = 0;
            if (!varint(plain, ctLen, at, largest) || !varint(plain, ctLen, at, delay) ||
                !varint(plain, ctLen, at, rangeCount) || !varint(plain, ctLen, at, firstRange))
                break;
            bool ok = true;
            for (uint64_t i = 0; i < rangeCount; ++i) {
                uint64_t gap = 0, len2 = 0;
                if (!varint(plain, ctLen, at, gap) || !varint(plain, ctLen, at, len2)) { ok = false; break; }
            }
            if (!ok) break;
            if (type == 0x03) {                        /* ECN counters */
                uint64_t a = 0, b = 0, c = 0;
                if (!varint(plain, ctLen, at, a) || !varint(plain, ctLen, at, b) ||
                    !varint(plain, ctLen, at, c)) break;
            }
            continue;
        }
        if (type == 0x06) {                            /* CRYPTO */
            uint64_t offset = 0, length = 0;
            if (!varint(plain, ctLen, at, offset) || !varint(plain, ctLen, at, length)) break;
            if (length > ctLen - at) break;
            insertCrypto(stream, offset, plain + at, size_t(length));
            at += size_t(length);
            continue;
        }
        break;  /* unknown or unsupported frame: stop, keep what we have */
    }

    if (stream.contiguous < 4) return false;
    size_t needed = 4 + be24(stream.bytes.data() + 1);
    if (needed > MaxHandshake) { releaseStream(stream); return false; }
    if (stream.contiguous < needed) return false;
    std::vector<uint8_t> hello(stream.bytes.begin(), stream.bytes.begin() + needed);
    releaseStream(stream);
    return tlsClientHelloSni(hello, sni);
}

}  // namespace linkatlas
