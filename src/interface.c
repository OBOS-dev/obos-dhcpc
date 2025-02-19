/*
 * src/eth.c
 *
 * Copyright (c) 2025 Omar Berrow
 */

#include <endian.h>
#include <stdint.h>
#include <stddef.h>

#include "dhcp.h"
#include "eth.h"
#include "ip.h"
#include "udp.h"

static uint32_t crc32_bytes(const void *data, size_t sz);

int interface_initialize(interface* i, const char* name, void* userdata, const char* hostname,  write_frame_t write_frame)
{
    if (!i)
        return 1;
    
    i->interface_name = name;
    i->interface_userdata = userdata;
    
    i->requested_hostname = hostname;
    
    i->write_frame = write_frame;
    
    return 0;
}

int interface_write(interface* i, const ethernet2_header* header_template, const void* data, size_t sz)
{
    if (!i || !data || !sz || !header_template)
        return 1;
    ethernet2_header hdr = *header_template;
    hdr.type = htobe16(hdr.type);
    frame f = {};
    frame_initialize(&f, NULL, sizeof(ethernet2_header)+sz+4);
    __builtin_memcpy(f.data, &hdr, sizeof(ethernet2_header));
    __builtin_memcpy(((char*)f.data)+sizeof(ethernet2_header), data, sz);
    uint32_t chksum = crc32_bytes(f.data, sizeof(ethernet2_header)+sz);
    __builtin_memcpy(((char*)f.data)+sizeof(ethernet2_header)+sz, &chksum, 4);
    i->write_frame(i, &f);
    frame_unref(&f);
    return 0;
}

static uint16_t ones_complement_sum(void *buffer, size_t size)
{
    uint16_t *p = buffer;
    int sum = 0;
    int i;
    for (i = 0; i < ((int)size & ~(1)); i += 2) {
        sum += be16toh(p[i >> 1]);
    }

    if (size & 1) {
        sum += ((uint8_t *)p)[i];
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;

    uint16_t ret = ~sum;
    return ret;
}

static uint16_t ip_checksum(ip_header* hdr)
{
    return ones_complement_sum(hdr, IPv4_GET_HEADER_LENGTH(hdr));
}

int transmit_udp_packet(interface* i, uint16_t dest_port, uint16_t src_port, const void* data, size_t size, ip_addr dest, ip_addr src, const mac_address* dest_mac)
{
    if (!i || !dest_port || !src_port || !data || !size || !dest_mac)
        return 1;
    frame f = {};
    frame_initialize(&f, NULL, sizeof(ip_header)+sizeof(udp_header)+size);
    ip_header* ip_hdr = f.data;
    ip_hdr->protocol = 0x11;
    ip_hdr->dest_address.addr = dest.addr;
    ip_hdr->version_hdrlen = (4 << 4) | (sizeof(*ip_hdr) / 4);
    ip_hdr->src_address.addr = src.addr;
    ip_hdr->time_to_live = 60;
    ip_hdr->packet_length = htobe16(sizeof(udp_header)+sizeof(ip_header)+size);
    ip_hdr->chksum = htobe16(ip_checksum(ip_hdr));
    udp_header* udp_hdr = (void*)(ip_hdr+1);
    udp_hdr->dest_port = htobe16(dest_port);
    udp_hdr->src_port = htobe16(src_port);
    udp_hdr->chksum = 0;
    udp_hdr->length = htobe16(size);
    void* buff = udp_hdr + 1;
    __builtin_memcpy(buff, data, size);

    ethernet2_header hdr = {};
    __builtin_memcpy(hdr.src, i->interface_mac, sizeof(i->interface_mac));
    __builtin_memcpy(hdr.dest, dest_mac, sizeof(*dest_mac));
    hdr.type = ETHERNET2_TYPE_IPv4;
    interface_write(i, &hdr, f.data, f.size);

    return 0;
}

void data_ready(void* user, interface* i, frame* f)
{
    // Filter packets that are UDP sent to DHCP_CLIENT_PORT, and are a broadcast packet, then pass it on to the DHCP layer.

    ethernet2_header* hdr = f->data;
    if (be16toh(hdr->type) != ETHERNET2_TYPE_IPv4)
        goto out;

    ip_header* ip = (ip_header*)(hdr+1);

    uint16_t hdr_chksum = ip->chksum;
    ip->chksum = 0;
    uint16_t our_chksum = ip_checksum(ip);
    ip->chksum = hdr_chksum;

    if (be16toh(hdr_chksum) != our_chksum)
        goto out;

    if (ip->protocol != 0x11 /* UDP */)
        goto out;
    if (i->routing_info.server_ip_address && i->routing_info.server_ip_address != ip->src_address.addr)
        goto out;
    if ((i->routing_info.ip_address && i->routing_info.ip_address != ip->dest_address.addr) && ip->dest_address.addr != 0xffffffff)
        goto out;

    // At this point, we know we have a UDP packet.
    // Just verify its destination port, then forward it.

    udp_header* udp = (udp_header*)(ip+1);
    if (be16toh(udp->dest_port) != DHCP_CLIENT_PORT)
        goto out;
    if (be16toh(udp->length) < sizeof(dhcp_header))
        goto out;

    f->refs++;
    dhcp_ready(i, f, udp);

    out:
    frame_unref(f);
}

int interface_ready(interface* i)
{
    if (!i) return 1;
    i->data_ready = data_ready;
    return 0;
}

int interface_stop(interface* i)
{
    if (!i) return 1;
    i->data_ready = NULL;
    return 0;
}

static bool initialized_crc32 = false;
static uint32_t crctab[256];

// For future reference, we cannot hardware-accelerate the crc32 algorithm as
// x86-64's crc32 uses a different polynomial than that of GPT.

static void crcInit()
{
    uint32_t crc = 0;
    for (uint16_t i = 0; i < 256; ++i)
    {
        crc = i;
        for (uint8_t j = 0; j < 8; ++j)
        {
            uint32_t mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        crctab[i] = crc;
    }
}
static uint32_t crc(const char *data, size_t len, uint32_t result)
{
    for (size_t i = 0; i < len; ++i)
        result = (result >> 8) ^ crctab[(result ^ data[i]) & 0xFF];
    return ~result;
}
static uint32_t crc32_bytes_from_previous(const void *data, size_t sz,
                                   uint32_t previousChecksum)
{
    if (!initialized_crc32)
    {
        crcInit();
        initialized_crc32 = true;
    }
    return crc(data, sz, ~previousChecksum);
}
static uint32_t crc32_bytes(const void *data, size_t sz)
{
    if (!initialized_crc32)
    {
        crcInit();
        initialized_crc32 = true;
    }
    return crc(data, sz, ~0U);
}
