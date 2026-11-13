#include <jni.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <string>
#include <strings.h>
#include <thread>
#include <vector>

#include "linkatlas/analyzer.h"
#include "linkatlas/tunnel.h"

namespace {

JavaVM *g_vm = nullptr;

struct Session {
    jobject service = nullptr;  // global ref to the VpnService
    jmethodID protect = nullptr;
    void *analyzer = nullptr;
    wd_tunnel *tunnel = nullptr;
    std::atomic<int> tun_fd{-1};
    std::atomic<bool> running{false};
    std::thread reader;
};

void on_output(void *ctx, const uint8_t *packet, size_t len) {
    int fd = static_cast<Session *>(ctx)->tun_fd.load();
    if (fd >= 0) {
        ssize_t n = write(fd, packet, len);
        (void)n;
    }
}

int on_protect(void *ctx, int fd) {
    auto *s = static_cast<Session *>(ctx);
    JNIEnv *env = nullptr;
    bool attached = false;
    if (g_vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) == JNI_EDETACHED) {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK) return -1;
        attached = true;
    }
    jboolean ok = env->CallBooleanMethod(s->service, s->protect, fd);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        ok = JNI_FALSE;
    }
    if (attached) g_vm->DetachCurrentThread();
    return ok ? 0 : -1;
}

bool public_address(uint8_t version, const uint8_t *ip) {
    if (version == 4) {
        uint8_t a = ip[0], b = ip[1];
        return !(a == 0 || a == 10 || a == 127 || a >= 224 ||
                 (a == 100 && b >= 64 && b <= 127) ||
                 (a == 169 && b == 254) ||
                 (a == 172 && b >= 16 && b <= 31) ||
                 (a == 192 && b == 168) ||
                 (a == 192 && b == 0) ||
                 (a == 198 && (b == 18 || b == 19 || b == 51)) ||
                 (a == 203 && b == 0));
    }
    bool all_zero = true;
    for (int i = 0; i < 16; ++i) all_zero &= ip[i] == 0;
    bool loopback = true;
    for (int i = 0; i < 15; ++i) loopback &= ip[i] == 0;
    loopback &= ip[15] == 1;
    return !all_zero && !loopback &&
           (ip[0] & 0xfe) != 0xfc &&
           !(ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) &&
           ip[0] != 0xff &&
           !(ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8);
}

/* The map download is the app's own infrastructure, not a service the user
   visited. It must never appear in the lists or on the map. */
bool app_infrastructure_host(const char *domain) {
    static const char *const kSuffixes[] = {"openfreemap.org"};
    if (!domain || !*domain) return false;
    const size_t length = std::strlen(domain);
    for (const char *suffix : kSuffixes) {
        const size_t suffix_length = std::strlen(suffix);
        if (length == suffix_length) {
            if (strcasecmp(domain, suffix) == 0) return true;
        } else if (length > suffix_length &&
                   domain[length - suffix_length - 1] == '.' &&
                   strcasecmp(domain + length - suffix_length, suffix) == 0) {
            return true;
        }
    }
    return false;
}

using AddressKey = std::pair<uint8_t, std::string>;

AddressKey address_key(uint8_t version, const uint8_t *address) {
    char text[INET6_ADDRSTRLEN]{};
    inet_ntop(version == 6 ? AF_INET6 : AF_INET, address, text, sizeof(text));
    return {version, text};
}

std::string fingerprintText(const wd_destination_summary &r) {
    if (!r.has_fingerprint) return "";
    if (!r.app_tcp_options_len) return "无选项";
    std::string text;
    {
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < r.app_tcp_options_len && i < 12; ++i) {
            text += hex[r.app_tcp_options[i] >> 4];
            text += hex[r.app_tcp_options[i] & 0x0f];
        }
    }
    return text;
}

void read_loop(Session *s) {
    std::vector<uint8_t> buf(65535);
    int fd = s->tun_fd.load();
    while (s->running.load()) {
        pollfd p{fd, POLLIN, 0};
        int r = poll(&p, 1, 200);
        if (r < 0 && errno != EINTR) break;
        if (r <= 0) continue;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        ssize_t n = read(fd, buf.data(), buf.size());
        if (n > 0) wd_tunnel_input(s->tunnel, buf.data(), static_cast<size_t>(n));
    }
}

}  // namespace

extern "C" {

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT jlong JNICALL Java_com_redsalmons_linkatlas_NativeTunnel_create(JNIEnv *env, jobject,
                                                                                jobject service) {
    auto *s = new Session();
    s->service = env->NewGlobalRef(service);
    jclass cls = env->GetObjectClass(service);
    s->protect = env->GetMethodID(cls, "protect", "(I)Z");
    env->DeleteLocalRef(cls);
    s->analyzer = wd_analyzer_create();
    s->tunnel = s->analyzer ? wd_tunnel_create(on_output, on_protect, s,
                                               wd_analyzer_on_event, s->analyzer) : nullptr;
    if (!s->tunnel) {
        wd_analyzer_destroy(s->analyzer);
        env->DeleteGlobalRef(s->service);
        delete s;
        return 0;
    }
    return reinterpret_cast<jlong>(s);
}

JNIEXPORT void JNICALL Java_com_redsalmons_linkatlas_NativeTunnel_start(JNIEnv *, jobject, jlong handle,
                                                                              jint tun_fd) {
    auto *s = reinterpret_cast<Session *>(handle);
    s->tun_fd.store(tun_fd);
    s->running.store(true);
    s->reader = std::thread(read_loop, s);
}

JNIEXPORT void JNICALL Java_com_redsalmons_linkatlas_NativeTunnel_destroy(JNIEnv *env, jobject,
                                                                                jlong handle) {
    auto *s = reinterpret_cast<Session *>(handle);
    s->running.store(false);
    if (s->reader.joinable()) s->reader.join();
    wd_tunnel_destroy(s->tunnel);
    s->tun_fd.store(-1);
    wd_analyzer_destroy(s->analyzer);
    env->DeleteGlobalRef(s->service);
    delete s;
}

JNIEXPORT void JNICALL Java_com_redsalmons_linkatlas_NativeTunnel_reset(JNIEnv *, jobject,
                                                                            jlong handle) {
    auto *s = reinterpret_cast<Session *>(handle);
    if (s && s->analyzer) wd_analyzer_reset(s->analyzer);
}

JNIEXPORT jobjectArray JNICALL Java_com_redsalmons_linkatlas_NativeTunnel_externalDestinations(
        JNIEnv *env, jobject, jlong handle) {
    jclass destinationClass = env->FindClass("com/redsalmons/linkatlas/DestinationObservation");
    if (!destinationClass) return nullptr;
    jmethodID constructor = env->GetMethodID(destinationClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V");
    if (!constructor) return nullptr;
    auto *s = reinterpret_cast<Session *>(handle);
    if (!s || !s->analyzer) return env->NewObjectArray(0, destinationClass, nullptr);
    wd_flow_summary flows[256];
    size_t count = wd_analyzer_snapshot(s->analyzer, flows, 256);
    // Learn the tile host's addresses first: a later flow to the same host may
    // arrive without SNI and would otherwise surface as a bare IP.
    std::vector<AddressKey> infrastructure;
    for (size_t i = 0; i < count; ++i) {
        const char *domain = flows[i].tls_sni[0] ? flows[i].tls_sni : flows[i].http_host;
        if (app_infrastructure_host(domain))
            infrastructure.push_back(address_key(flows[i].flow.ipver, flows[i].flow.dst));
    }
    auto is_infrastructure = [&](uint8_t version, const uint8_t *address) {
        const AddressKey key = address_key(version, address);
        for (const auto &entry : infrastructure)
            if (entry == key) return true;
        return false;
    };
    std::vector<std::pair<std::string, std::string>> destinations;
    for (size_t i = 0; i < count; ++i) {
        if (flows[i].closed || !public_address(flows[i].flow.ipver, flows[i].flow.dst)) continue;
        if (flows[i].protocol[0] == WD_PROTOCOL_DNS) continue;
        const char *domain = flows[i].tls_sni[0] ? flows[i].tls_sni : flows[i].http_host;
        if (app_infrastructure_host(domain)) continue;
        if (is_infrastructure(flows[i].flow.ipver, flows[i].flow.dst)) continue;
        char text[INET6_ADDRSTRLEN];
        int family = flows[i].flow.ipver == 6 ? AF_INET6 : AF_INET;
        if (inet_ntop(family, flows[i].flow.dst, text, sizeof(text)))
            destinations.emplace_back(text, domain);
    }
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(destinations.size()), destinationClass, nullptr);
    jsize index = 0;
    for (const auto &destination : destinations) {
        jstring ip = env->NewStringUTF(destination.first.c_str());
        jstring domain = env->NewStringUTF(destination.second.c_str());
        jobject value = env->NewObject(destinationClass, constructor, ip, domain);
        env->SetObjectArrayElement(out, index++, value);
        env->DeleteLocalRef(value);
        env->DeleteLocalRef(ip);
        env->DeleteLocalRef(domain);
    }
    return out;
}

JNIEXPORT jobjectArray JNICALL Java_com_redsalmons_linkatlas_NativeTunnel_websiteVisits(
        JNIEnv *env, jobject, jlong handle) {
    jclass cls = env->FindClass("com/redsalmons/linkatlas/WebsiteVisit");
    if (!cls) return nullptr;
    jmethodID constructor = env->GetMethodID(cls, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;JJJJILjava/lang/String;I)V");
    if (!constructor) return nullptr;
    auto *s = reinterpret_cast<Session *>(handle);
    if (!s || !s->analyzer) return env->NewObjectArray(0, cls, nullptr);
    std::vector<wd_destination_summary> records;
    size_t count = wd_analyzer_destinations(s->analyzer, nullptr, 0);
    do {
        records.resize(count + 32);
        count = wd_analyzer_destinations(s->analyzer, records.data(), records.size());
    } while (count > records.size());
    records.resize(count);
    std::vector<AddressKey> infrastructure;
    for (const auto &record : records)
        if (app_infrastructure_host(record.domain))
            infrastructure.push_back(address_key(record.ipver, record.dst));
    std::vector<wd_destination_summary> external;
    for (const auto &record : records) {
        bool is_infrastructure = false;
        const AddressKey key = address_key(record.ipver, record.dst);
        for (const auto &entry : infrastructure)
            if (entry == key) { is_infrastructure = true; break; }
        if (is_infrastructure) continue;
        /* A resolver is infrastructure, not a visited site: its "domain" is whatever
           the client asked for, which the analyzer deliberately never records. */
        if (record.protocol == WD_PROTOCOL_DNS) continue;
        if (app_infrastructure_host(record.domain)) continue;
        if (public_address(record.ipver, record.dst)) external.push_back(record);
    }
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(external.size()), cls, nullptr);
    jsize index = 0;
    for (const auto &record : external) {
        char text[INET6_ADDRSTRLEN]{};
        inet_ntop(record.ipver == 6 ? AF_INET6 : AF_INET, record.dst, text, sizeof(text));
        jstring ip = env->NewStringUTF(text);
        jstring domain = env->NewStringUTF(record.domain);
        jstring fingerprint = env->NewStringUTF(fingerprintText(record).c_str());
        jobject value = env->NewObject(cls, constructor, ip, domain,
            static_cast<jlong>(record.tcp_connections), static_cast<jlong>(record.udp_flows),
            static_cast<jlong>(record.bytes[0]), static_cast<jlong>(record.bytes[1]),
            static_cast<jint>(record.protocol), fingerprint,
            static_cast<jint>(record.domain_source));
        env->SetObjectArrayElement(out, index++, value);
        env->DeleteLocalRef(value);
        env->DeleteLocalRef(ip);
        env->DeleteLocalRef(domain);
        env->DeleteLocalRef(fingerprint);
    }
    return out;
}

}  // extern "C"
