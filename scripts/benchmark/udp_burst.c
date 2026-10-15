// Send a fixed number of 64-byte Ethernet IPv4/UDP frames over a veth lab.
// The 22-byte UDP payload makes 14 + 20 + 8 + 22 = 64 bytes on Ethernet,
// excluding the frame check sequence. This helper measures no off-host path.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define BATCH 64
#define PAYLOAD_BYTES 22

static double seconds(const struct timespec *start, const struct timespec *end) {
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_nsec - start->tv_nsec) / 1e9;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s packet-count\n", argv[0]);
        return 2;
    }
    char *end = NULL;
    unsigned long target = strtoul(argv[1], &end, 10);
    if (!end || *end || target == 0) {
        fprintf(stderr, "packet-count must be a positive integer\n");
        return 2;
    }

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(9000),
    };
    if (inet_pton(AF_INET, "198.18.0.1", &dst.sin_addr) != 1) {
        fprintf(stderr, "invalid destination address\n"); return 1;
    }

    char payload[BATCH][PAYLOAD_BYTES] = {{0}};
    struct iovec iov[BATCH];
    struct mmsghdr msgs[BATCH];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH; i++) {
        iov[i].iov_base = payload[i];
        iov[i].iov_len = sizeof(payload[i]);
        msgs[i].msg_hdr.msg_name = &dst;
        msgs[i].msg_hdr.msg_namelen = sizeof(dst);
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    struct timespec begin, finish;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    unsigned long sent = 0;
    while (sent < target) {
        unsigned int count = (target - sent > BATCH) ? BATCH : (unsigned int)(target - sent);
        int n = sendmmsg(fd, msgs, count, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("sendmmsg"); close(fd); return 1;
        }
        if (n == 0) { fprintf(stderr, "sendmmsg made no progress\n"); close(fd); return 1; }
        sent += (unsigned long)n;
        if ((unsigned int)n < count) {
            for (int i = 0; i < n; i++) msgs[i].msg_len = 0;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &finish);
    double elapsed = seconds(&begin, &finish);
    printf("sent=%lu send_seconds=%.9f sender_pps=%.2f\n", sent, elapsed, sent / elapsed);
    close(fd);
    return 0;
}
