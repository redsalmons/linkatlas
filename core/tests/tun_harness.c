/* Linux-only harness: runs the tunnel on a TUN device. Used by tests/netns_e2e.sh. */
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "watchdog/analyzer.h"
#include "watchdog/tunnel.h"

static unsigned long hooked[2];
static volatile sig_atomic_t stop;

static void on_signal(int sig) {
    (void)sig;
    stop = 1;
}

static void on_output(void *ctx, const uint8_t *packet, size_t len) {
    ssize_t n = write(*(int *)ctx, packet, len);
    (void)n;
}

static void on_packet(void *analyzer, const uint8_t *packet, size_t len, wd_direction dir) {
    __atomic_add_fetch(&hooked[dir], 1, __ATOMIC_RELAXED);
    wd_analyzer_on_packet(analyzer, packet, len, dir);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <ifname> <seconds>\n", argv[0]);
        return 2;
    }
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    if (fd < 0 || ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("tun");
        return 1;
    }
    void *analyzer = wd_analyzer_create();
    wd_tunnel *t = wd_tunnel_create(on_output, NULL, &fd, on_packet, analyzer);
    if (!t) return 1;
    printf("ready\n");
    fflush(stdout);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    time_t end = time(NULL) + atoi(argv[2]);
    uint8_t buf[65536];
    while (!stop && time(NULL) < end) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 100) <= 0) continue;
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) wd_tunnel_input(t, buf, (size_t)n);
    }
    wd_tunnel_destroy(t);
    wd_analyzer_destroy(analyzer);
    printf("hook outbound=%lu inbound=%lu\n", hooked[WD_DIR_OUTBOUND], hooked[WD_DIR_INBOUND]);
    return 0;
}
