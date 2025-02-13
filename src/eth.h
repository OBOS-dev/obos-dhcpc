/*
 * src/eth.h
 *
 * Copyright (c) 2025 Omar Berrow
 */

#pragma once

#include <stdint.h>
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
typedef struct frame frame;

struct frame {
    void* data;
    size_t size;
    size_t refs;
};
// To be defined by the backend.

// Must zero *f, increment refs, set unref to a callback that frees the frame, and make a copy of data.
// If data is NULL, allocate sz bytes, zero them, and set f->data to that pointer.
extern void frame_initialize(frame* f, const void* data, size_t sz);
// Decrements refs, and if it is zero, free data.
extern void frame_unref(frame* f);

typedef void (*write_frame_t)(interface*, frame*);

struct interface {
    const char* interface_name;
    void* interface_userdata;

    const char* requested_hostname;

    // Called by the backend whenever there is data ready for the DHCP client to read from.
    void* data_ready_userdata;
    void (*data_ready)(void* user, interface* i, frame* f);

    write_frame_t write_frame;
};

// Return 0 on success, >0 on error.
int interface_initialize(interface* i, const char* name, void* userdata, const char* hostname, write_frame_t write_frame);

int interface_write(interface* i, const ethernet2_header* header_template, const void* data, size_t sz);

// Internal.
// Used around DHCPDISCOVER code to enable/disable reception of packets.

// Return 0 on success, >0 on error.
int interface_ready(interface* i);

// Return 0 on success, >0 on error.
int interface_stop(interface* i);
