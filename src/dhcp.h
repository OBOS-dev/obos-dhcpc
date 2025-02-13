/*
 * src/dhcp.h
 *
 * Copyright (c) 2025 Omar Berrow
 */

#include <stdint.h>
#include <stddef.h>

#include "eth.h"

enum {
    BOOTREQUEST = 1,
    BOOTREPLY = 2,
};

enum {
    DHCP_SERVER_PORT = 67,
    DHCP_CLIENT_PORT = 68,
};

enum {
    DHCP_FLAGS_BROADCAST = (1<<0),
};

enum {
    DHCP_OPT_PAD = 0,
    /*
     * "If both the subnet mask and the router option are specified in a DHCP
     * reply, the subnet mask option MUST be first."
     * From RFC2132 Section 3.3
     */
    DHCP_OPT_SUBNET_MASK = 1,
    DHCP_OPT_DOMAIN_NAME = 15,
    DHCP_OPT_ENABLE_IP_FORWARDING = 19,
    DHCP_OPT_BROADCAST_ADDRESS = 28,
    DHCP_OPT_STATIC_ROUTE = 33,
    DHCP_OPT_ARP_TIMEOUT = 35,
    DHCP_OPT_REQUEST_IP = 50,
    DHCP_OPT_LEASE_TIME = 51,
    DHCP_OPT_OVERLOAD_OPT = 52,
    DHCP_OPT_DHCP_MSG_TYPE = 53,
    DHCP_OPT_PARAMETER_REQUESTS = 55,

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
    char payload[];
};

typedef struct dhcp_header {
    uint8_t op, htype, hlen, hops /* we're a DHCP client, set to zero. */;

    uint32_t xid;

    // secs: "seconds elapsed since client began address acquisition or renewal process."
    uint16_t secs, flags;

    uint32_t ciaddr, yiaddr, siaddr, giaddr, chaddr;

    uint8_t chaddr[16];

    char sname[64]; // hostname

    char file[128];

    char options[];
} dhcp_header;

// Returns 0 on success, >0 on failure
int dhcp_discover(interface* i);
