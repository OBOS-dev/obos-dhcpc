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

#include <obos/syscall.h>
#include <obos/error.h>

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
    int fd = (int)(uintptr_t)i->interface_userdata;
    write(fd, f->data, f->size);
}

void *interface_recv(void* user)
{
    interface* i = user;
    
    while (1)
    {
        obos_status status = OBOS_STATUS_SUCCESS;
        handle irp_desc = (int)(uintptr_t)i->interface_userdata;
        status = syscall5(Sys_IRPCreate, (uintptr_t)&irp_desc, 0, 0, 0 /* IRP_READ */, NULL);
        if (obos_is_error(status))
            continue;;
        status = syscall1(Sys_IRPSubmit, irp_desc);
        if (obos_is_error(status))
            continue;;
        size_t nBlkRead = 0;
        syscall4(Sys_IRPWait, irp_desc, &status, &nBlkRead, true);
        if (obos_is_error(status))
            continue;;

        void* buff = malloc(nBlkRead);
        
        irp_desc = (int)(uintptr_t)i->interface_userdata;
        syscall5(Sys_IRPCreate, (uintptr_t)&irp_desc, 0, nBlkRead, 0 /* IRP_READ */, buff);
        syscall1(Sys_IRPSubmit, irp_desc);
        status = OBOS_STATUS_SUCCESS;
        nBlkRead = 0;
        syscall4(Sys_IRPWait, irp_desc, &status, &nBlkRead, true);

        frame f = {};
        frame_initialize(&f, buff, nBlkRead);
        i->data_ready(i->data_ready_userdata, i, &f);
        free(buff);
    }
    return NULL;
}

enum { IOCTL_IFACE_MAC_REQUEST = 0xe100 };

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "%s interface\n", argv[0]);
        return 1;
    }

    static interface net_interface = {};
    char* interface_path = NULL;
    size_t interface_path_len = snprintf(NULL,0, "/dev/%s", argv[1]);
    interface_path = malloc(interface_path_len+1);
    snprintf(interface_path,interface_path_len+1, "/dev/%s", argv[1]);
    int interface_fd = open(interface_path, O_RDWR);
    if (interface_fd < 0)
    {
        perror("open(interface_path, O_RDWR)");
        return 1;
    }
    ioctl(interface_fd, IOCTL_IFACE_MAC_REQUEST, &net_interface.interface_mac);

    char* hostname = malloc(128);
    size_t len_hostname = 128;
    while (gethostname(hostname, len_hostname))
    {
        len_hostname *= 1.5f;
        hostname = realloc(hostname, len_hostname);
    }

    interface_initialize(&net_interface, argv[1], (void*)(uintptr_t)interface_fd, hostname, write_frame);
    pthread_t thr;

    pthread_create(
        &thr, 
        NULL,
        interface_recv, &net_interface);

    dhcp_discover(&net_interface);

    // pthread_cancel(thr);

    return 0;
}
