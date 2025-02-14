/*
 * src/dhcp.h
 *
 * Copyright (c) 2025 Omar Berrow
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "eth.h"
#include "udp.h"

enum {
    BOOTREQUEST = 1,
    BOOTREPLY = 2,
};

enum {
    DHCP_SERVER_PORT = 67,
    DHCP_CLIENT_PORT = 68,
};

enum {
    DHCP_FLAGS_BROADCAST = (1<<15),
};

enum {
    DHCP_OPT_PAD = 0,
    /*
     * "If both the subnet mask and the router option are specified in a DHCP
     * reply, the subnet mask option MUST be first."
     * From RFC2132 Section 3.3
     */
    DHCP_OPT_SUBNET_MASK = 1,
    DHCP_OPT_ROUTER = 3,
    DHCP_OPT_DOMAIN_NAME = 15,
    DHCP_OPT_ENABLE_IP_FORWARDING = 19,
    DHCP_OPT_BROADCAST_ADDRESS = 28,
    DHCP_OPT_ARP_TIMEOUT = 35,
    DHCP_OPT_REQUEST_IP = 50,
    DHCP_OPT_LEASE_TIME = 51,
    DHCP_OPT_OVERLOAD_OPT = 52,
    DHCP_OPT_DHCP_MSG_TYPE = 53,
    DHCP_OPT_SERVER_IDENTIFIER = 54,
    DHCP_OPT_PARAMETER_REQUESTS = 55,
    DHCP_OPT_CLIENT_IDENITIFER = 61,

    DHCP_OPT_END = 255 /* 0xff */,
    DHCP_OPT_MAGIC = 0x63825363,
};

enum {
    DHCPDISCOVER = 1,
    DHCPOFFER,
    DHCPREQUEST,
    DHCPDECLINE,
    DHCPACK,
    DHCPNAK,
    DHCPRELEASE,
    DHCPINFORM,
};

typedef struct dhcp_option {
    uint8_t opcode;
    uint8_t length;
    uint8_t payload[];
} __attribute__((packed)) dhcp_option;

// Same thing as dhcp_option, but payload has a fixed size of 64-bytes.
typedef struct dhcp_option_short {
    uint8_t opcode;
    uint8_t length;
    uint8_t payload[64];
} __attribute__((packed)) dhcp_option_short;

typedef struct dhcp_header {
    uint8_t op, htype, hlen, hops /* we're a DHCP client, set to zero. */;

    uint32_t xid;

    // secs: "seconds elapsed since client began address acquisition or renewal process."
    uint16_t secs, flags;

    uint32_t ciaddr, yiaddr, siaddr, giaddr;

    uint8_t chaddr[16];

    char sname[64];

    char file[128];

    uint8_t options[];
} __attribute__((packed)) dhcp_header;

// Returns 0 on success, >0 on failure
// Returns -1 to specify that you should retry the action.
int dhcp_discover(interface* i);

// Returns a random number.
// To be implemented by the backend.
uint32_t dhcp_generate_xid();

// Any of the [ci/yi/si/gi]addr fields are to be set by the caller.
// Variadic arguments are of type dhcp_option*
void dhcp_format_header(interface* i, frame* out, uint8_t op, uint32_t xid, size_t nOptions, ...);

// cb should return zero to continue, or one to abort the loop.
void dhcp_foreach_option(dhcp_header* hdr, size_t hdr_size, int(*cb)(dhcp_header* hdr, dhcp_option* opt, void* user), void* user);

void dhcp_ready(interface* i, frame* f, udp_header* udp_hdr);