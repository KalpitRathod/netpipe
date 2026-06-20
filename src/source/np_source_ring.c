/*
 * np_source_ring.c — Linux AF_PACKET + PACKET_MMAP packet source
 *
 * Bug 5.1: The entire implementation is Linux-specific (uses
 * <linux/if_packet.h>, AF_PACKET, PACKET_MMAP).  On non-Linux systems
 * (macOS, FreeBSD), we provide a stub that returns a clear runtime error
 * so the file still compiles and links.
 */

#ifdef __linux__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "../pipeline/np_pipeline.h"

typedef struct {
    int                fd;
    void              *ring;
    size_t             ring_size;
    struct tpacket_req req;
    int                current_frame;
    volatile bool      is_stopped;
} ring_priv_t;

static np_err_t ring_src_open(np_source_t *src)
{
    (void)src;
    return NP_OK;
}

static np_err_t ring_src_next(np_source_t *src, np_packet_t **out)
{
    ring_priv_t *p = src->priv;
    if (p->is_stopped) {
        return NP_ERR_EOF;
    }

    // Locate current frame header in memory mapped ring buffer
    unsigned char *frame_ptr = (unsigned char *)p->ring + ((size_t)p->current_frame * p->req.tp_frame_size);
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)frame_ptr;

    // Check status to see if the frame contains a packet owned by the user-space application
    while (!(hdr->tp_status & TP_STATUS_USER)) {
        if (p->is_stopped) {
            return NP_ERR_EOF;
        }

        // Frame belongs to kernel. Let's poll on socket to wait for a packet.
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = p->fd;
        pfd.events = POLLIN;

        int poll_rc = poll(&pfd, 1, 10); // 10ms timeout
        if (p->is_stopped) {
            return NP_ERR_EOF;
        }
        if (poll_rc < 0) {
            return NP_ERR_GENERIC;
        }
        if (poll_rc == 0) {
            return NP_ERR_TIMEOUT;
        }

        /* Bug 5.2: poll returned > 0 but we only checked tp_status.
         * If the underlying socket has an error (POLLERR/POLLHUP,
         * e.g. interface went down), poll returns positive but
         * tp_status is not TP_STATUS_USER, so we'd return TIMEOUT
         * and the pipeline would spin tightly.  Detect socket errors
         * explicitly and return IO so the pipeline can react. */
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            NP_LOG_ERROR("ring source: socket error (revents=0x%x)", pfd.revents);
            return NP_ERR_IO;
        }

        // Spurious wakeup check
        if (!(hdr->tp_status & TP_STATUS_USER)) {
            return NP_ERR_TIMEOUT;
        }
    }

    /* Bug H7 fix: TPACKET_V2 requires a read memory barrier between
     * reading tp_status == TP_STATUS_USER and reading any other field
     * of the tpacket2_hdr (tp_mac, tp_snaplen, tp_sec, tp_nsec) or
     * the packet data itself.  Without the barrier, on weakly-ordered
     * CPUs (ARM, POWER), the compiler/CPU may reorder the subsequent
     * reads before the tp_status read, observing stale data from a
     * previous frame.  The kernel documents this requirement in
     * Documentation/networking/packet_mmap.rst.
     *
     * __sync_synchronize() is a full memory barrier; on x86 it
     * compiles to `mfence`, on ARM to `dmb ish`. */
    __sync_synchronize();

    // Zero-copy capture achieved: packet data is already in mapped buffer.
    // Allocate pipeline packet to copy/forward the data.
    np_packet_t *pkt = np_packet_alloc(hdr->tp_snaplen);
    if (!pkt) {
        // Return frame ownership to kernel so we don't stall the ring buffer
        hdr->tp_status = TP_STATUS_KERNEL;
        p->current_frame = (p->current_frame + 1) % (int)p->req.tp_frame_nr;
        return NP_ERR_NOMEM;
    }

    /* Bug 7 fix: validate tp_mac and tp_snaplen against the frame size
     * before memcpy.  A malformed or malicious frame (or a kernel bug)
     * could set tp_mac larger than tp_frame_size, causing an
     * out-of-bounds read from the mmap'd ring.  Similarly, tp_snaplen
     * could exceed the remaining bytes.  Reject the frame and advance. */
    if (hdr->tp_mac >= p->req.tp_frame_size ||
        hdr->tp_snaplen > p->req.tp_frame_size - hdr->tp_mac) {
        NP_LOG_WARN("ring source: malformed frame (tp_mac=%u tp_snaplen=%u frame_size=%u) — skipping",
                    hdr->tp_mac, hdr->tp_snaplen, p->req.tp_frame_size);
        hdr->tp_status = TP_STATUS_KERNEL;
        p->current_frame = (p->current_frame + 1) % (int)p->req.tp_frame_nr;
        np_packet_free(pkt);
        return NP_ERR_PROTO;
    }

    unsigned char *pkt_data = frame_ptr + hdr->tp_mac;
    memcpy(pkt->raw, pkt_data, hdr->tp_snaplen);
    pkt->caplen = hdr->tp_snaplen;
    pkt->wirelen = hdr->tp_len;
    pkt->ts.tv_sec = hdr->tp_sec;
    pkt->ts.tv_nsec = (long)hdr->tp_nsec;

    // Release frame ownership back to kernel
    hdr->tp_status = TP_STATUS_KERNEL;

    // Move to next frame
    p->current_frame = (p->current_frame + 1) % (int)p->req.tp_frame_nr;

    *out = pkt;
    return NP_OK;
}

static void ring_src_stop(np_source_t *src)
{
    ring_priv_t *p = src->priv;
    if (p) {
        p->is_stopped = true;
    }
}

static void ring_src_close(np_source_t *src)
{
    ring_priv_t *p = src->priv;
    if (p) {
        p->is_stopped = true;
        if (p->ring && p->ring != MAP_FAILED) {
            munmap(p->ring, p->ring_size);
            p->ring = NULL;
        }
        if (p->fd >= 0) {
            close(p->fd);
            p->fd = -1;
        }
    }
}

static void ring_src_free(np_source_t *src)
{
    ring_src_close(src);
    free(src->priv);
    free(src);
}

static const struct np_source_ops ring_ops = {
    .open  = ring_src_open,
    .next  = ring_src_next,
    .stop  = ring_src_stop,
    .close = ring_src_close,
    .free  = ring_src_free,
};

np_source_t *np_source_ring(const char *device,
                             uint16_t eth_proto,
                             int      ring_blocks)
{
    /* FIX (issue: ETH_P_ALL by default + hardcoded ring size):
     * Accept a caller-specified EtherType (in HOST byte order) and a
     * caller-specified ring block count.  Defaults preserve the
     * historical behaviour (ETH_P_ALL + 8 blocks) so existing callers
     * using the wrapper still get the same capture profile. */
    if (eth_proto == 0)    eth_proto    = ETH_P_ALL;
    if (ring_blocks <= 0)  ring_blocks  = 8;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        NP_LOG_ERROR("socket(AF_PACKET): %s (are you root?)", strerror(errno));
        return NULL;
    }

    // Locate interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        NP_LOG_ERROR("ioctl(SIOCGIFINDEX) for '%s' failed: %s", device, strerror(errno));
        close(fd);
        return NULL;
    }
    int ifindex = ifr.ifr_ifindex;

    // Bind socket to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    /* FIX: use the caller-specified EtherType for the bind, so the
     * kernel only queues frames of that protocol onto the ring. */
    sll.sll_protocol = (uint16_t)htons(eth_proto);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        NP_LOG_ERROR("bind AF_PACKET to index %d failed: %s", ifindex, strerror(errno));
        close(fd);
        return NULL;
    }

    // Set TPACKET_V2 version
    int version = TPACKET_V2;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        NP_LOG_ERROR("setsockopt(PACKET_VERSION): %s", strerror(errno));
        close(fd);
        return NULL;
    }

    // Configure memory ring parameters
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = 4096 * 256; // 1 MB block size
    req.tp_frame_size = 2048;       // 2 KB frame size
    req.tp_block_nr   = (unsigned)ring_blocks;  /* FIX: caller-specified */
    req.tp_frame_nr   = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        NP_LOG_ERROR("setsockopt(PACKET_RX_RING): %s", strerror(errno));
        close(fd);
        return NULL;
    }

    // Mmap memory shared with kernel
    size_t ring_size = req.tp_block_size * req.tp_block_nr;
    void *ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        NP_LOG_ERROR("mmap zero-copy ring failed: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    ring_priv_t *p = calloc(1, sizeof(*p));
    if (!p) {
        munmap(ring, ring_size);
        close(fd);
        return NULL;
    }

    p->fd = fd;
    p->ring = ring;
    p->ring_size = ring_size;
    p->req = req;
    p->current_frame = 0;
    p->is_stopped = false;

    np_source_t *src = calloc(1, sizeof(*src));
    if (!src) {
        free(p);
        munmap(ring, ring_size);
        close(fd);
        return NULL;
    }

    src->ops = &ring_ops;
    src->priv = p;
    src->linktype = NP_LINK_ETHERNET; // AF_PACKET Raw yields Ethernet frames
    snprintf(src->name, sizeof(src->name), "ring:%s", device);

    NP_LOG_INFO("zero-copy packet ring opened on '%s' (size=%lu MB, frames=%d)",
                device, (unsigned long)(ring_size / (1024 * 1024)), req.tp_frame_nr);

    return src;
}

#else  /* !__linux__ */

/*
 * Non-Linux stub (Bug 5.1): AF_PACKET + PACKET_MMAP is Linux-only.
 * On macOS, FreeBSD, etc., we return a clear runtime error so the
 * caller can fall back to np_source_live() (libpcap).
 */

#include <stdlib.h>
#include <stddef.h>
#include "netpipe.h"
#include "../log/np_log.h"

np_source_t *np_source_ring(const char *device,
                             uint16_t eth_proto,
                             int      ring_blocks)
{
    (void)device; (void)eth_proto; (void)ring_blocks;
    NP_LOG_ERROR("np_source_ring: AF_PACKET zero-copy ring capture is only "
                 "available on Linux.  Use -i <device> (libpcap) instead.");
    return NULL;
}

#endif  /* __linux__ */
