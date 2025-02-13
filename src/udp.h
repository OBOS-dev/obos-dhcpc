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

void transmit_udp_packet(interface* i, uint16_t port, const void* data, size_t size, ip_addr dest, ip_addr src);
