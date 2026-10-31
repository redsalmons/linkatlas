#include <jni.h>
#include <poll.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <thread>
#include <vector>

#include "watchdog/analyzer.h"
#include "watchdog/tunnel.h"

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

JNIEXPORT jlong JNICALL Java_com_redsalmons_mobilewatchdog_NativeTunnel_create(JNIEnv *env, jobject,
                                                                                jobject service) {
    auto *s = new Session();
    s->service = env->NewGlobalRef(service);
    jclass cls = env->GetObjectClass(service);
    s->protect = env->GetMethodID(cls, "protect", "(I)Z");
    env->DeleteLocalRef(cls);
    s->analyzer = wd_analyzer_create();
    s->tunnel = wd_tunnel_create(on_output, on_protect, s, wd_analyzer_on_packet, s->analyzer);
    if (!s->tunnel) {
        wd_analyzer_destroy(s->analyzer);
        env->DeleteGlobalRef(s->service);
        delete s;
        return 0;
    }
    return reinterpret_cast<jlong>(s);
}

JNIEXPORT void JNICALL Java_com_redsalmons_mobilewatchdog_NativeTunnel_start(JNIEnv *, jobject, jlong handle,
                                                                              jint tun_fd) {
    auto *s = reinterpret_cast<Session *>(handle);
    s->tun_fd.store(tun_fd);
    s->running.store(true);
    s->reader = std::thread(read_loop, s);
}

JNIEXPORT void JNICALL Java_com_redsalmons_mobilewatchdog_NativeTunnel_destroy(JNIEnv *env, jobject,
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

}  // extern "C"
