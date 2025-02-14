/*
 * src/main.c
 *
 * Copyright (c) 2025 Omar Berrow
 */

#include <complex.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <pcap/pcap.h>

#include "dhcp.h"
#include "eth.h"

void frame_initialize(frame* f, const void* data, size_t sz)
{
    if (data)
        f->data = memcpy(malloc(sz), data, sz);
    else
        f->data = calloc(sz, 1);
    f->size = sz;
    f->refs++;
}

void frame_unref(frame* f)
{
    if (!(--f->refs))
        free(f->data);
}

extern frame* frame_alloc() { return calloc(1, sizeof(frame)); }

uint32_t dhcp_generate_xid()
{
    struct timeval rand = {};
    gettimeofday(&rand, NULL);
    return (uint32_t)(rand.tv_sec & 0xffffffff);
}

__attribute__((format(printf, 1, 2))) int dhcp_log(const char* format, ...)
{
    va_list list;
    va_start(list, format);
    int ret = vprintf(format, list);
    va_end(list);
    return ret;
}

void write_frame (interface* i, frame* f)
{
    pcap_inject(i->interface_userdata, f->data, f->size);
}

void recv_packet(u_char *user, const struct pcap_pkthdr *info, const u_char *data)
{
    interface* i = (void*)user;
    if (!i->data_ready)
        return;
    frame f = {};
    frame_initialize(&f, data, info->caplen);
    i->data_ready(i-> data_ready_userdata, i, &f);
}

void *interface_recv(void* user)
{
    interface* i = user;
    pcap_loop(i->interface_userdata, 0, recv_packet, user);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "%s interface\n", argv[0]);
        return 1;
    }
    static char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(argv[1], 262144, 0, 1, errbuf);
    if (!handle) 
    {
        fprintf(stderr, "Could not open interface %s. Error message: %s\n", argv[1], errbuf);
        return -1;
    }

    struct sockaddr_ll daddr = {};

    int sock = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1)
    {
        perror("socket");
        return -1;
    }

    memset(&daddr, 0, sizeof(struct sockaddr_ll));
    daddr.sll_family = AF_PACKET;
    daddr.sll_protocol = IPPROTO_RAW;
    daddr.sll_ifindex = if_nametoindex(argv[1]);
    if (bind(sock, (struct sockaddr*) &daddr, sizeof(daddr)) < 0) {
        perror("bind");
        close(sock);
        pcap_close(handle);
        return -1;
    }

    pcap_set_immediate_mode(handle, 1);
    pcap_setnonblock(handle, 1, errbuf);

    struct ifreq req = {};
    strncpy(req.ifr_name, argv[1], 16);
    if (ioctl(sock, SIOCGIFHWADDR, &req) == -1)
    {
        perror("ioctl");
        close(sock);
        pcap_close(handle);
        return -1;
    }

    static interface net_interface = {};
    memcpy(net_interface.interface_mac, req.ifr_hwaddr.sa_data, 6);

    interface_initialize(&net_interface, argv[1], handle, "obos-dhcpd-test", write_frame);
    pthread_t thr;

    pthread_create(
        &thr, 
        NULL,
        interface_recv, &net_interface);

    pcap_activate(handle);

    dhcp_discover(&net_interface);

    pthread_cancel(thr);
    pcap_close(handle);

    return 0;
}
