/*
 * src/udp.h
 *
 * Copyright (c) 2025 Omar Berrow
 */

#pragma once

#include <stdint.h>

#include "ip.h"
#include "eth.h"

typedef struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t chksum;
} udp_header;

// Returns 0 on success, >0 on failure
// This function expects that the MAC address of the destination is already known.
// This is usually the case, as the DHCP client is only ever broadcasting packets, or replying to packets. 
int transmit_udp_packet(interface* i, uint16_t dest_port, uint16_t src_port, const void* data, size_t size, ip_addr dest, ip_addr src, const mac_address* dest_mac);
