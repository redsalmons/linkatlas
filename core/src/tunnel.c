#include "watchdog/tunnel.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define QUEUE_MAX 4096
#define TCP_TMR_MS 250
#define TCP_CHUNK 16384
#define UDP_IDLE_MS 60000
#define UDP_DNS_IDLE_MS 10000
#define IO_BUF 65536

typedef struct packet {
    struct packet *next;
    size_t len;
    uint8_t data[];
} packet;

enum { CONN_TCP, CONN_UDP };

typedef struct conn {
    struct conn *next;
    wd_tunnel *t;
    int type;
    int fd;
    struct tcp_pcb *tpcb;
    struct udp_pcb *upcb;
    int connected;
    int local_eof;  /* app closed its side */
    int remote_eof; /* server closed its side */
    int sock_shut;
    int dead;
    short revents;
    uint64_t last_active;
    uint8_t *pending; /* app -> server, not yet sent to the socket */
    size_t pending_len, pending_cap;
    uint8_t out[TCP_CHUNK]; /* server -> app, not yet accepted by lwIP (TCP only) */
    size_t out_len, out_off;
} conn;

struct wd_tunnel {
    wd_output_fn output;
    wd_protect_fn protect;
    void *ctx;
    wd_packet_fn hook;
    void *hook_ctx;

    struct netif netif;
    struct tcp_pcb *listen_tcp;
    struct udp_pcb *listen_udp;
    conn *conns;
    size_t nconns;

    pthread_t thread;
    int running;
    int wake[2];

    pthread_mutex_t qmu;
    packet *qhead, *qtail;
    size_t qlen;

    uint8_t buf[IO_BUF];  /* scratch for UDP payloads */
    uint8_t obuf[IO_BUF]; /* linearized packets towards the device */
};

/* Required by the lwIP port (LWIP_RAND). */
unsigned int lwip_port_rand(void) {
#if defined(__APPLE__) || defined(__ANDROID__)
    return arc4random();
#else
    return (unsigned int)random();
#endif
}

static pthread_once_t lwip_once = PTHREAD_ONCE_INIT;
static void lwip_init_once(void) { lwip_init(); }

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }

static socklen_t to_sockaddr(const ip_addr_t *a, u16_t port, struct sockaddr_storage *ss) {
    memset(ss, 0, sizeof(*ss));
    if (IP_IS_V6(a)) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        memcpy(&s6->sin6_addr, ip_2_ip6(a)->addr, 16);
#ifdef __APPLE__
        s6->sin6_len = sizeof(*s6);
#endif
        return sizeof(*s6);
    }
    struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(port);
    s4->sin_addr.s_addr = ip_2_ip4(a)->addr;
#ifdef __APPLE__
    s4->sin_len = sizeof(*s4);
#endif
    return sizeof(*s4);
}

/* Non-blocking socket connected (or connecting) to the original destination. */
static int open_socket(wd_tunnel *t, int type, const ip_addr_t *dst, u16_t port) {
    struct sockaddr_storage ss;
    socklen_t len = to_sockaddr(dst, port, &ss);
    int fd = socket(ss.ss_family, type, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    if ((t->protect && t->protect(t->ctx, fd) != 0) ||
        (connect(fd, (struct sockaddr *)&ss, len) != 0 && errno != EINPROGRESS)) {
        close(fd);
        return -1;
    }
    return fd;
}

static conn *conn_new(wd_tunnel *t, int type, int fd) {
    conn *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->t = t;
    c->type = type;
    c->fd = fd;
    c->last_active = now_ms();
    c->next = t->conns;
    t->conns = c;
    t->nconns++;
    return c;
}

static void tcp_detach(conn *c) {
    tcp_arg(c->tpcb, NULL);
    tcp_recv(c->tpcb, NULL);
    tcp_err(c->tpcb, NULL);
}

static void tcp_conn_abort(conn *c) {
    if (c->tpcb) {
        tcp_detach(c);
        tcp_abort(c->tpcb);
        c->tpcb = NULL;
    }
    c->dead = 1;
}

static void tcp_conn_close(conn *c) {
    if (c->tpcb) {
        tcp_detach(c);
        if (tcp_close(c->tpcb) != ERR_OK) tcp_abort(c->tpcb);
        c->tpcb = NULL;
    }
    c->dead = 1;
}

static void udp_conn_close(conn *c) {
    if (c->upcb) {
        udp_recv(c->upcb, NULL, NULL);
        udp_remove(c->upcb);
        c->upcb = NULL;
    }
    c->dead = 1;
}

/* ---- lwIP callbacks (tunnel thread) ---- */

static err_t netif_output(struct netif *netif, struct pbuf *p) {
    wd_tunnel *t = netif->state;
    const uint8_t *data = p->payload;
    if (p->len != p->tot_len) {
        pbuf_copy_partial(p, t->obuf, p->tot_len, 0);
        data = t->obuf;
    }
    if (t->hook) t->hook(t->hook_ctx, data, p->tot_len, WD_DIR_INBOUND);
    t->output(t->ctx, data, p->tot_len);
    return ERR_OK;
}

static err_t netif_output_v4(struct netif *netif, struct pbuf *p, const ip4_addr_t *addr) {
    (void)addr;
    return netif_output(netif, p);
}

static err_t netif_output_v6(struct netif *netif, struct pbuf *p, const ip6_addr_t *addr) {
    (void)addr;
    return netif_output(netif, p);
}

static err_t netif_init_cb(struct netif *netif) {
    netif->output = netif_output_v4;
    netif->output_ip6 = netif_output_v6;
    return ERR_OK;
}

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    conn *c = arg;
    (void)pcb;
    (void)err;
    if (!p) {
        c->local_eof = 1;
        return ERR_OK;
    }
    size_t need = c->pending_len + p->tot_len;
    if (need > c->pending_cap) {
        size_t cap = c->pending_cap ? c->pending_cap : 4096;
        while (cap < need) cap *= 2;
        uint8_t *n = realloc(c->pending, cap);
        if (!n) return ERR_MEM; /* lwIP keeps the pbuf and retries */
        c->pending = n;
        c->pending_cap = cap;
    }
    pbuf_copy_partial(p, c->pending + c->pending_len, p->tot_len, 0);
    c->pending_len = need;
    pbuf_free(p);
    return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err) {
    conn *c = arg;
    (void)err;
    if (!c) return;
    c->tpcb = NULL; /* already freed by lwIP */
    c->dead = 1;
}

static err_t tcp_accept_cb(void *arg, struct tcp_pcb *pcb, err_t err) {
    wd_tunnel *t = arg;
    if (err != ERR_OK || !pcb) return ERR_VAL;
    /* With PRETEND_TCP the accepted pcb's local address is the original destination. */
    int fd = open_socket(t, SOCK_STREAM, &pcb->local_ip, pcb->local_port);
    conn *c = fd >= 0 ? conn_new(t, CONN_TCP, fd) : NULL;
    if (!c) {
        if (fd >= 0) close(fd);
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    c->tpcb = pcb;
    tcp_arg(pcb, c);
    tcp_recv(pcb, tcp_recv_cb);
    tcp_err(pcb, tcp_err_cb);
    return ERR_OK;
}

static void udp_drop_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    (void)arg;
    (void)addr;
    (void)port;
    pbuf_free(p);
    udp_recv(pcb, NULL, NULL);
    udp_remove(pcb);
}

static void udp_flow_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    conn *c = arg;
    (void)pcb;
    (void)addr;
    (void)port;
    if (!c->dead) {
        pbuf_copy_partial(p, c->t->buf, p->tot_len, 0);
        if (send(c->fd, c->t->buf, p->tot_len, MSG_NOSIGNAL) >= 0) c->last_active = now_ms();
    }
    pbuf_free(p);
}

/* A new UDP flow; the datagram that created the pcb is delivered to it after we return. */
static void udp_listen_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    wd_tunnel *t = arg;
    (void)p;
    /* For a new flow lwIP passes the original destination as addr/port. */
    int fd = open_socket(t, SOCK_DGRAM, addr, port);
    conn *c = fd >= 0 ? conn_new(t, CONN_UDP, fd) : NULL;
    if (!c) {
        if (fd >= 0) close(fd);
        udp_recv(pcb, udp_drop_cb, NULL);
        return;
    }
    c->upcb = pcb;
    c->connected = 1;
    udp_recv(pcb, udp_flow_cb, c);
}

/* ---- tunnel thread ---- */

static void tcp_flush_out(conn *c) {
    while (c->out_len > c->out_off && c->tpcb) {
        size_t room = tcp_sndbuf(c->tpcb);
        size_t n = c->out_len - c->out_off;
        if (n > room) n = room;
        if (n == 0) break;
        err_t e = tcp_write(c->tpcb, c->out + c->out_off, (u16_t)n, TCP_WRITE_FLAG_COPY);
        if (e == ERR_MEM) break; /* retry after ACKs free the send queue */
        if (e != ERR_OK) {
            tcp_conn_abort(c);
            return;
        }
        c->out_off += n;
    }
    if (c->tpcb) tcp_output(c->tpcb);
    if (c->out_off == c->out_len) c->out_off = c->out_len = 0;
}

static void tcp_process(conn *c) {
    short re = c->revents;
    if (!c->connected) {
        if (!(re & (POLLOUT | POLLERR | POLLHUP))) return;
        int err = 0;
        socklen_t l = sizeof(err);
        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &l);
        if (err) {
            tcp_conn_abort(c); /* resets the app's connection */
            return;
        }
        c->connected = 1;
    }

    /* app -> server */
    if (c->pending_len) {
        ssize_t n = send(c->fd, c->pending, c->pending_len, MSG_NOSIGNAL);
        if (n > 0) {
            memmove(c->pending, c->pending + n, c->pending_len - (size_t)n);
            c->pending_len -= (size_t)n;
            for (size_t left = (size_t)n; left > 0;) {
                u16_t chunk = left > 0xffff ? 0xffff : (u16_t)left;
                tcp_recved(c->tpcb, chunk);
                left -= chunk;
            }
        } else if (n < 0 && !would_block()) {
            tcp_conn_abort(c);
            return;
        }
    }
    if (c->local_eof && !c->pending_len && !c->sock_shut) {
        shutdown(c->fd, SHUT_WR);
        c->sock_shut = 1;
    }

    /* server -> app */
    if (c->out_len) tcp_flush_out(c);
    if (c->dead) return;
    if (!c->remote_eof && !c->out_len && (re & (POLLIN | POLLHUP | POLLERR))) {
        ssize_t n = recv(c->fd, c->out, sizeof(c->out), 0);
        if (n > 0) {
            c->out_len = (size_t)n;
            tcp_flush_out(c);
        } else if (n == 0) {
            c->remote_eof = 1;
            tcp_shutdown(c->tpcb, 0, 1);
        } else if (!would_block()) {
            tcp_conn_abort(c);
            return;
        }
    }
    if (c->dead) return;
    if (c->local_eof && c->remote_eof && !c->pending_len && !c->out_len) tcp_conn_close(c);
}

static void udp_process(conn *c, uint64_t now) {
    if (c->revents & (POLLIN | POLLERR)) {
        ssize_t n = recv(c->fd, c->t->buf, IO_BUF, 0);
        if (n >= 0) {
            struct pbuf *b = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM);
            if (b) {
                memcpy(b->payload, c->t->buf, (size_t)n);
                udp_sendfrom(c->upcb, b, &c->upcb->local_ip, c->upcb->local_port);
                pbuf_free(b);
            }
            c->last_active = now;
        } else if (!would_block()) {
            udp_conn_close(c);
            return;
        }
    }
    uint64_t idle = c->upcb->local_port == 53 ? UDP_DNS_IDLE_MS : UDP_IDLE_MS;
    if (now - c->last_active > idle) udp_conn_close(c);
}

static void drain_input(wd_tunnel *t) {
    char sink[256];
    while (read(t->wake[0], sink, sizeof(sink)) > 0) {
    }
    pthread_mutex_lock(&t->qmu);
    packet *list = t->qhead;
    t->qhead = t->qtail = NULL;
    t->qlen = 0;
    pthread_mutex_unlock(&t->qmu);

    while (list) {
        packet *next = list->next;
        if (t->hook) t->hook(t->hook_ctx, list->data, list->len, WD_DIR_OUTBOUND);
        struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)list->len, PBUF_RAM);
        if (p) {
            memcpy(p->payload, list->data, list->len);
            if (t->netif.input(p, &t->netif) != ERR_OK) pbuf_free(p);
        }
        free(list);
        list = next;
    }
}

static void reap(wd_tunnel *t) {
    for (conn **pp = &t->conns; *pp;) {
        conn *c = *pp;
        if (c->dead) {
            *pp = c->next;
            close(c->fd);
            free(c->pending);
            free(c);
            t->nconns--;
        } else {
            pp = &c->next;
        }
    }
}

static void *tunnel_main(void *arg) {
    wd_tunnel *t = arg;
    struct pollfd *pfds = NULL;
    conn **map = NULL;
    size_t cap = 0;
    uint64_t last_tmr = now_ms();
    unsigned ticks = 0;

    while (__atomic_load_n(&t->running, __ATOMIC_ACQUIRE)) {
        size_t n = t->nconns + 1;
        if (n > cap) {
            cap = n * 2;
            pfds = realloc(pfds, cap * sizeof(*pfds));
            map = realloc(map, cap * sizeof(*map));
            if (!pfds || !map) break;
        }
        pfds[0] = (struct pollfd){t->wake[0], POLLIN, 0};
        size_t i = 1;
        int busy = 0;
        for (conn *c = t->conns; c; c = c->next) {
            short ev = 0;
            c->revents = 0;
            if (c->type == CONN_UDP) {
                ev = POLLIN;
            } else if (c->tpcb) {
                if (!c->connected || c->pending_len) ev |= POLLOUT;
                if (c->connected && !c->remote_eof && !c->out_len && tcp_sndbuf(c->tpcb) > 0) ev |= POLLIN;
                if (c->out_len) busy = 1;
            }
            pfds[i] = (struct pollfd){c->fd, ev, 0};
            map[i++] = c;
        }

        uint64_t now = now_ms();
        int timeout = (int)(TCP_TMR_MS - (now - last_tmr < TCP_TMR_MS ? now - last_tmr : TCP_TMR_MS));
        if (busy && timeout > 10) timeout = 10;
        if (poll(pfds, (nfds_t)i, timeout) < 0 && errno != EINTR) break;
        for (size_t k = 1; k < i; ++k) map[k]->revents = pfds[k].revents;

        drain_input(t);

        now = now_ms();
        for (conn *c = t->conns; c; c = c->next) {
            if (c->dead) continue;
            if (c->type == CONN_TCP) {
                if (c->tpcb) tcp_process(c);
            } else {
                udp_process(c, now);
            }
        }

        if (now - last_tmr >= TCP_TMR_MS) {
            last_tmr = now;
            tcp_tmr();
            if ((++ticks & 3) == 0) {
#if IP_REASSEMBLY
                ip_reass_tmr();
#endif
#if LWIP_IPV6
                nd6_tmr();
#if LWIP_IPV6_REASS
                ip6_reass_tmr();
#endif
#endif
            }
        }
        reap(t);
    }
    free(pfds);
    free(map);
    return NULL;
}

wd_tunnel *wd_tunnel_create(wd_output_fn output, wd_protect_fn protect, void *ctx,
                            wd_packet_fn hook, void *hook_ctx) {
    if (!output) return NULL;
    pthread_once(&lwip_once, lwip_init_once);

    wd_tunnel *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->output = output;
    t->protect = protect;
    t->ctx = ctx;
    t->hook = hook;
    t->hook_ctx = hook_ctx;
    pthread_mutex_init(&t->qmu, NULL);
    if (pipe(t->wake) != 0) {
        free(t);
        return NULL;
    }
    for (int k = 0; k < 2; ++k) {
        fcntl(t->wake[k], F_SETFL, fcntl(t->wake[k], F_GETFL) | O_NONBLOCK);
        fcntl(t->wake[k], F_SETFD, FD_CLOEXEC);
    }

    ip4_addr_t addr4, mask, gw;
    ip6_addr_t addr6;
    netif_add_noaddr(&t->netif, t, netif_init_cb, ip_input);
    ip4_addr_set_loopback(&addr4);
    ip4_addr_set_any(&mask);
    ip4_addr_set_any(&gw);
    netif_set_addr(&t->netif, &addr4, &mask, &gw);
    ip6_addr_set_loopback(&addr6);
    netif_add_ip6_address(&t->netif, &addr6, NULL);
    netif_set_up(&t->netif);
    netif_set_link_up(&t->netif);
    netif_set_default(&t->netif);
    /* Accept TCP/UDP to any destination address (heiher/lwip extension). */
    netif_set_flags(&t->netif, NETIF_FLAG_PRETEND_TCP);
    netif_set_flags(&t->netif, NETIF_FLAG_PRETEND_UDP);

    struct tcp_pcb *tl = tcp_new_ip_type(IPADDR_TYPE_ANY);
    t->listen_udp = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (!tl || !t->listen_udp) goto fail;
    tcp_bind_netif(tl, &t->netif);
    tcp_bind(tl, NULL, 0);
    t->listen_tcp = tcp_listen(tl);
    if (!t->listen_tcp) goto fail;
    tcp_arg(t->listen_tcp, t);
    tcp_accept(t->listen_tcp, tcp_accept_cb);
    udp_bind_netif(t->listen_udp, &t->netif);
    udp_bind(t->listen_udp, NULL, 0);
    udp_recv(t->listen_udp, udp_listen_cb, t);

    t->running = 1;
    if (pthread_create(&t->thread, NULL, tunnel_main, t) != 0) goto fail;
    return t;

fail:
    t->running = 0;
    if (t->listen_tcp) tcp_close(t->listen_tcp);
    else if (tl) tcp_close(tl);
    if (t->listen_udp) udp_remove(t->listen_udp);
    netif_remove(&t->netif);
    close(t->wake[0]);
    close(t->wake[1]);
    free(t);
    return NULL;
}

void wd_tunnel_input(wd_tunnel *t, const uint8_t *data, size_t len) {
    if (!t || !data || len == 0 || len > 0xffff) return;
    packet *p = malloc(sizeof(*p) + len);
    if (!p) return;
    p->next = NULL;
    p->len = len;
    memcpy(p->data, data, len);
    pthread_mutex_lock(&t->qmu);
    if (t->qlen >= QUEUE_MAX) {
        pthread_mutex_unlock(&t->qmu);
        free(p);
        return;
    }
    if (t->qtail) t->qtail->next = p;
    else t->qhead = p;
    t->qtail = p;
    t->qlen++;
    pthread_mutex_unlock(&t->qmu);
    ssize_t w = write(t->wake[1], "x", 1);
    (void)w;
}

void wd_tunnel_destroy(wd_tunnel *t) {
    if (!t) return;
    __atomic_store_n(&t->running, 0, __ATOMIC_RELEASE);
    ssize_t w = write(t->wake[1], "x", 1);
    (void)w;
    pthread_join(t->thread, NULL);

    for (conn *c = t->conns; c; c = c->next) {
        if (c->type == CONN_TCP) tcp_conn_abort(c);
        else udp_conn_close(c);
    }
    reap(t);
    tcp_close(t->listen_tcp);
    udp_remove(t->listen_udp);
    netif_remove(&t->netif);

    for (packet *p = t->qhead; p;) {
        packet *next = p->next;
        free(p);
        p = next;
    }
    close(t->wake[0]);
    close(t->wake[1]);
    pthread_mutex_destroy(&t->qmu);
    free(t);
}
