/*
 * src/eth.h
 *
 * Copyright (c) 2025 Omar Berrow
 */

#pragma once

#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef uint8_t mac_address[6];
#define BROADCAST_MAC_ADDRESS {0xff,0xff,0xff,0xff,0xff,0xff,}

enum {
    ETHERNET2_TYPE_IPv4 = 0x0800,
    ETHERNET2_TYPE_ARP  = 0x0806,
    ETHERNET2_TYPE_IPv6 = 0x86dd,
};

typedef struct ethernet2_header {
    mac_address dest;
    mac_address src;
    uint16_t type;
} __attribute__((packed)) ethernet2_header;

typedef struct interface interface;
typedef uint32_t routing_entry;
typedef struct frame frame;
typedef struct { uint32_t src; uint32_t dest; } static_routing_entry;

struct frame {
    void* data;
    size_t size;
    size_t refs;
    frame *next, *prev;
};
// To be defined by the backend.

// Must zero *f, increments 'refs', and make a copy of data.
// If data is NULL, allocate sz bytes, zero them, and set f->data to that pointer.
extern void frame_initialize(frame* f, const void* data, size_t sz);
// Decrements refs, and if it is zero, free data.
extern void frame_unref(frame* f);
extern frame* frame_alloc();

typedef void (*write_frame_t)(interface*, frame*);

struct interface {
    const char* interface_name;
    void* interface_userdata;
    mac_address interface_mac;

    const char* requested_hostname;

    // Called by the backend whenever there is data ready for the DHCP client to read from.
    void* data_ready_userdata;
    void (*data_ready)(void* user, interface* i, frame* f);

    write_frame_t write_frame;

    uint32_t active_xid;
    struct {
        frame* head;
        frame* tail;
        atomic_flag lock;
    } ready_packets;

    // The accepted configuration settings from a DHCP server.
    struct {
        struct dhcp_header* hdr;
        frame hdr_frame;
        
        uint32_t server_ip_address;
        
        uint32_t ip_address;
        uint32_t broadcast_ip_address;
        uint32_t subnet_mask;
        
        bool enable_ipv4_forwarding;

        routing_entry* routers;
        size_t nRouters;
        frame routers_buffer;

        static_routing_entry* static_routes;
        size_t nStaticRoutes;
        frame static_routes_buffer;
    } routing_info;
};

#define dhcp_acquire_spinlock(x) do {\
    while (atomic_flag_test_and_set_explicit(&(x), memory_order_acq_rel))\
        ;\
} while(0)
#define dhcp_release_spinlock(x) do {\
    atomic_flag_clear_explicit(&(x), memory_order_relaxed);\
} while(0)

// Return 0 on success, >0 on error.
int interface_initialize(interface* i, const char* name, void* userdata, const char* hostname, write_frame_t write_frame);

int interface_write(interface* i, const ethernet2_header* header_template, const void* data, size_t sz);

// Internal.
// Used around DHCPDISCOVER code to enable/disable reception of packets.

// Return 0 on success, >0 on error.
int interface_ready(interface* i);

// Return 0 on success, >0 on error.
int interface_stop(interface* i);

extern __attribute__((format(printf, 1, 2))) int dhcp_log(const char* format, ...);
