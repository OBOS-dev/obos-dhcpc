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

typedef struct gateway_user {
    ip_addr src;
    ip_addr dest;
} gateway_user;

enum {
    IP_ENTRY_ENABLE_ICMP_ECHO_REPLY = 1<<0,
    IP_ENTRY_ENABLE_ARP_REPLY = 1<<1,
    IP_ENTRY_IPv4_FORWARDING = 1<<2,
};

typedef struct ip_table_entry_user {
    ip_addr address;
    ip_addr broadcast;
    uint32_t subnet;
    uint32_t ip_entry_flags;
} ip_table_entry_user;

enum {
    // Each ethernet driver should define this
    // argp points to a `mac_address`
    IOCTL_IFACE_MAC_REQUEST = 0xe100,
    // implementations of the following ioctls are in
    // tables.h 
    IOCTL_IFACE_ADD_IP_TABLE_ENTRY,
    IOCTL_IFACE_REMOVE_IP_TABLE_ENTRY,
    IOCTL_IFACE_ADD_ROUTING_TABLE_ENTRY,
    IOCTL_IFACE_REMOVE_ROUTING_TABLE_ENTRY,
    IOCTL_IFACE_SET_IP_TABLE_ENTRY,
    IOCTL_IFACE_CLEAR_ARP_CACHE,
    IOCTL_IFACE_CLEAR_ROUTE_CACHE,
    IOCTL_IFACE_GET_IP_TABLE,
    IOCTL_IFACE_GET_ROUTING_TABLE,
    IOCTL_IFACE_SET_DEFAULT_GATEWAY,
    IOCTL_IFACE_UNSET_DEFAULT_GATEWAY,
    IOCTL_IFACE_INITIALIZE,
};

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

    // TODO(oberrow): Cache this information?
    dhcp_discover(&net_interface);

    unlink("/etc/resolv.conf");
    if (net_interface.routing_info.dns_server)
    {
        int fd = open("/etc/resolv.conf", O_WRONLY|O_TRUNC|O_CREAT);
        char* resolv_conf = NULL;
        ip_addr dns_server = {.addr=net_interface.routing_info.dns_server};
        size_t resolv_conf_len = snprintf(NULL, 0, "# DO NOT WRITE! YOUR CHANGES WILL BE OVERWRITTEN!\nnameserver %u.%u.%u.%u\n", 
            dns_server.comp1,dns_server.comp2,dns_server.comp3,dns_server.comp4        
        );
        resolv_conf = malloc(resolv_conf_len+1);
        snprintf(resolv_conf, resolv_conf_len+1, "# DO NOT WRITE! YOUR CHANGES WILL BE OVERWRITTEN!\nnameserver %u.%u.%u.%u\n", 
            dns_server.comp1,dns_server.comp2,dns_server.comp3,dns_server.comp4        
        );
        write(fd, resolv_conf, resolv_conf_len);
        fsync(fd);
        close(fd);
    }
    ioctl(interface_fd, IOCTL_IFACE_INITIALIZE);
    do {
        ip_table_entry_user entry = {};
        entry.ip_entry_flags = (net_interface.routing_info.enable_ipv4_forwarding ? IP_ENTRY_IPv4_FORWARDING : 0);
        entry.ip_entry_flags |= IP_ENTRY_ENABLE_ARP_REPLY;
        entry.ip_entry_flags |= IP_ENTRY_ENABLE_ICMP_ECHO_REPLY;
        entry.address.addr = net_interface.routing_info.ip_address;
        entry.broadcast.addr = net_interface.routing_info.broadcast_ip_address;
        entry.subnet = net_interface.routing_info.subnet_mask;
        ioctl(interface_fd, IOCTL_IFACE_ADD_IP_TABLE_ENTRY, &entry);
    } while(0);
    for (size_t i = 0; i < net_interface.routing_info.nStaticRoutes; i++)
    {
        gateway_user route = {
            .src.addr=net_interface.routing_info.static_routes[i].src,
            .dest.addr=net_interface.routing_info.static_routes[i].dest,
        };
        ioctl(interface_fd, IOCTL_IFACE_ADD_ROUTING_TABLE_ENTRY, &route);
    }
    if (net_interface.routing_info.nRouters > 0)
        ioctl(interface_fd, IOCTL_IFACE_SET_DEFAULT_GATEWAY, &net_interface.routing_info.routers[0]);

    // pthread_cancel(thr);

    return 0;
}
