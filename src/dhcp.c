/*
 * src/dhcp.c
 *
 * Copyright (c) 2025 Omar Berrow
 */

#include <endian.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdatomic.h>

#include "eth.h"
#include "dhcp.h"
#include "udp.h"
#include "ip.h"

// Any of the [ci/yi/si/gi]addr fields are to be set by the caller. 
// Variadic arguments are of type dhcp_option
void dhcp_format_header(interface* i, frame* out, uint8_t op, uint32_t xid, size_t nOptions, ...)
{
    if (op != BOOTREQUEST && op != BOOTREPLY)
        return;

    size_t sz = sizeof(dhcp_header);
    
    va_list list;
    va_list list2;
    va_start(list, nOptions);
    va_copy(list2, list);
    for (size_t i = 0; i < nOptions; i++)
    {
        dhcp_option *opt = va_arg(list, dhcp_option*);
        if (opt->opcode != DHCP_OPT_PAD)
            sz += (opt->length+sizeof(*opt));
        else
            sz += 1;
    }
    sz += 5 /* for the magic number and end tag */;
    va_end(list);

    frame_initialize(out, NULL, sz);

    dhcp_header* hdr = out->data;
    hdr->xid = htobe32(xid);
    hdr->op = op;
    hdr->hlen = 6;
    hdr->htype = 1;
    hdr->flags = 0;
    __builtin_memcpy(hdr->chaddr, &i->interface_mac, sizeof(mac_address));

    size_t offset = 0;
    *(uint32_t*)hdr->options = htobe32(DHCP_OPT_MAGIC);
    offset += 4;
    for (size_t i = 0; i < nOptions; i++)
    {
        dhcp_option* opt = va_arg(list2, dhcp_option*);
        if (opt->opcode != DHCP_OPT_PAD)
        {
            __builtin_memcpy(&hdr->options[offset], opt, (opt->length+sizeof(*opt)));
            offset += (opt->length+sizeof(*opt));
        }
        else
        {
            hdr->options[offset] = DHCP_OPT_PAD;
            offset += 1;
        }
    }
    hdr->options[offset] = DHCP_OPT_END;
    va_end(list2);
}

void dhcp_foreach_option(dhcp_header* hdr, size_t hdr_size, int(*cb)(dhcp_header* hdr, dhcp_option* opt, void* user), void* user)
{
    uint32_t offset = 0;
    if (be32toh(*(uint32_t*)hdr->options) != DHCP_OPT_MAGIC)
        return;
    offset += 4;
    enum {
        OPTION_OVERLOAD_NONE = 0b00,
        OPTION_OVERLOAD_FILE = 0b01,
        OPTION_OVERLOAD_SNAME = 0b10,
    } opt_overload = OPTION_OVERLOAD_NONE;
    bool abort_loop = false;
    for (size_t i = 0; offset < (hdr_size-sizeof(dhcp_header)) && !abort_loop; i++)
    {
        dhcp_option* opt = (dhcp_option*)&hdr->options[offset];
        if (opt->opcode == DHCP_OPT_END)
            break;
        switch (opt->opcode)
        {
            case DHCP_OPT_PAD:
                offset += 1;
                continue;
            case DHCP_OPT_OVERLOAD_OPT:
                opt_overload = opt->payload[0];
                offset += sizeof(*opt)+opt->length;
                break;
            default:
                if (cb(hdr, opt, user) == 1)
                    abort_loop = true;
                offset += sizeof(*opt)+opt->length;
                break;
        }
    }
    if (opt_overload & OPTION_OVERLOAD_SNAME)
    {
        offset = 0;
        for (size_t i = 0; offset < sizeof(hdr->sname) && !abort_loop; i++)
        {
            dhcp_option* opt = (dhcp_option*)&hdr->sname[offset];
            if (opt->opcode == DHCP_OPT_END)
                break;
            switch (opt->opcode)
            {
                case DHCP_OPT_PAD:
                    offset += 1;
                    continue;
                default:
                    if (cb(hdr, opt, user) == 1)
                        abort_loop = true;
                    offset += sizeof(*opt)+opt->length;
                    break;
            }
        }
    }
    if (opt_overload & OPTION_OVERLOAD_FILE)
    {
        offset = 0;
        for (size_t i = 0; offset < sizeof(hdr->file) && !abort_loop; i++)
        {
            dhcp_option* opt = (dhcp_option*)&hdr->file[offset];
            if (opt->opcode == DHCP_OPT_END)
                break;
            switch (opt->opcode)
            {
                case DHCP_OPT_PAD:
                    offset += 1;
                    continue;
                default:
                    if (cb(hdr, opt, user) == 1)
                        abort_loop = true;
                    offset += sizeof(*opt)+opt->length;
                    break;
            }
        }
    }
}

size_t dhcp_strlen(const char* str)
{
    if (!str) return 0;
    size_t i = 0;
    while (str[i++])
        asm volatile ("" ::"r"(str):"memory");
    return i;
}

static int find_offer(dhcp_header* hdr, dhcp_option* opt, void* user)
{
    bool* result = user;
    switch (opt->opcode)
    {
        case DHCP_OPT_DHCP_MSG_TYPE:
        {
            if (opt->payload[0] == DHCPOFFER)
                *result = true;
            return 1;
        }
        default: break;
    }
    return 0;
}
static int is_ack_cb(dhcp_header* hdr, dhcp_option* opt, void* user)
{
    uint8_t* result = user;
    switch (opt->opcode)
    {
        case DHCP_OPT_DHCP_MSG_TYPE:
        {
            if (opt->payload[0] == DHCPACK || opt->payload[0] == DHCPNAK)
            {
                result[0] = true;
                result[1] = opt->payload[0];
            }
            return 1;
        }
        default: break;
    }
    return 0;
}
static int initalize_routing_info(dhcp_header* hdr, dhcp_option* opt, void* user)
{
    interface* i = user;
    switch (opt->opcode)
    {
        case DHCP_OPT_BROADCAST_ADDRESS:
        {
            if (opt->length < 4)
                break;
            i->routing_info.broadcast_ip_address = *(uint32_t*)opt->payload;
            break;
        }
        case DHCP_OPT_ROUTER:
        {
            if (opt->length < 4 || (opt->length % 4) != 0)
                break;
            frame_initialize(&i->routing_info.routers_buffer, opt->payload, opt->length);
            i->routing_info.routers = i->routing_info.routers_buffer.data;
            i->routing_info.nRouters = opt->length / 4;
            for (size_t j = 0; j < i->routing_info.nRouters; j++)
                dhcp_log("DHCP: Found router: %u.%u.%u.%u\n", opt->payload[0+j*4], opt->payload[1+j*4], opt->payload[2+j*4], opt->payload[3+j*4]);
            break;
        }
        case DHCP_OPT_STATIC_ROUTE:
        {
            if (opt->length < 8 || (opt->length % 8) != 0)
                break;
            frame_initialize(&i->routing_info.static_routes_buffer, opt->payload, opt->length);
            i->routing_info.static_routes = i->routing_info.static_routes_buffer.data;
            i->routing_info.nStaticRoutes = opt->length / 8;
            for (size_t j = 0; j < i->routing_info.nRouters; j++)
                dhcp_log("DHCP: Found static route: %u.%u.%u.%u->%u.%u.%u.%u\n",
                    be32toh(i->routing_info.static_routes[j].src) & 0xff000000,
                    be32toh(i->routing_info.static_routes[j].src) & 0x00ff0000,
                    be32toh(i->routing_info.static_routes[j].src) & 0x0000ff00,
                    be32toh(i->routing_info.static_routes[j].src) & 0x000000ff,
                    be32toh(i->routing_info.static_routes[j].dest) & 0xff000000,
                    be32toh(i->routing_info.static_routes[j].dest) & 0x00ff0000,
                    be32toh(i->routing_info.static_routes[j].dest) & 0x0000ff00,
                    be32toh(i->routing_info.static_routes[j].dest) & 0x000000ff
                );

        }
        case DHCP_OPT_SUBNET_MASK:
        {
            if (opt->length != 4)
                break;
            i->routing_info.subnet_mask = *(uint32_t*)opt->payload;
            dhcp_log("DHCP: Subnet mask: %u.%u.%u.%u\n", opt->payload[0], opt->payload[1], opt->payload[2], opt->payload[3]);
            break;
        }
        case DHCP_OPT_ENABLE_IP_FORWARDING:
        {
            if (opt->length != 1)
                break;
            i->routing_info.enable_ipv4_forwarding = *(uint8_t*)opt->payload;
            dhcp_log("DHCP: %s IPv4 forwarding\n", i->routing_info.enable_ipv4_forwarding ? "Enabling" : "disabling");
            break;
        }
        default: break;
    }
    return 0;
}

// Returns 0 on success, >0 on failure
int dhcp_discover(interface* i)
{
    if (!i)
        return 1;
    static dhcp_option_short parameter_req = { 
        .opcode = DHCP_OPT_PARAMETER_REQUESTS,
        .length = 6,
        .payload = {
            DHCP_OPT_ROUTER,
            DHCP_OPT_SUBNET_MASK,
            DHCP_OPT_STATIC_ROUTE,
            DHCP_OPT_BROADCAST_ADDRESS,
            DHCP_OPT_ENABLE_IP_FORWARDING,
            DHCP_OPT_DOMAIN_NAME_SERVER,
        }
    };
    dhcp_option_short msg_type = { .opcode = DHCP_OPT_DHCP_MSG_TYPE, .length=1, .payload[0]=DHCPDISCOVER };
    static dhcp_option_short maximum_message_size = {
        .opcode = DHCP_OPT_MAX_MSG_SIZE,
        .length = 2,
        .payload = {
            0x02, // 0x240=576
            0x40, // 0x240=576
        }
    };

    dhcp_option_short domain_name_static = {};

    size_t domain_name_len = dhcp_strlen(i->requested_hostname);
    dhcp_option* domain_name = domain_name_len < 64 ? (dhcp_option*)&domain_name_static : NULL;
    frame domain_name_buffer = {};
    if (domain_name_len)
    {
        if (!domain_name)
        {
            frame_initialize(&domain_name_buffer, NULL, domain_name_len-1+sizeof(dhcp_option));
            domain_name = domain_name_buffer.data;
        }
        domain_name->length = domain_name_len-1;
        domain_name->opcode = DHCP_OPT_DOMAIN_NAME;
        __builtin_memcpy(domain_name->payload, i->requested_hostname, domain_name_len-1);
    }

    frame discover = {};
    dhcp_format_header(
        i, 
        &discover, 
        BOOTREQUEST, 
        dhcp_generate_xid(), 
        3 + ((domain_name == NULL) ? 0 : 1),
        &maximum_message_size, 
        &msg_type,
        &parameter_req, 
        domain_name
    );
    mac_address dest_mac = BROADCAST_MAC_ADDRESS;
    i->active_xid = be32toh(((dhcp_header*)discover.data)->xid);
    interface_ready(i);
    transmit_udp_packet(
        i, 
        DHCP_SERVER_PORT, DHCP_CLIENT_PORT, 
        discover.data, discover.size, 
        (ip_addr){.addr=0xffffffff}, (ip_addr){.addr=0x0},
        &dest_mac
    );
    frame_unref(&discover);

    // Wait for an offer
    frame* offer_frame = NULL;
    ethernet2_header* offer_eth_hdr = NULL;
    dhcp_header* offer = NULL;
    size_t sz_offer = 0;
    while (!offer_frame)
    {
        interface_ready(i);
        while (!i->ready_packets.head)
            asm volatile ("" ::"r"(i->ready_packets.head) :"memory");
        interface_stop(i);
        
        for (frame* curr = i->ready_packets.head; curr; )
        {
            dhcp_acquire_spinlock(i->ready_packets.lock);
            i->ready_packets.head = curr->next;
            if (curr->next)
                curr->next->prev = NULL;
            if (i->ready_packets.tail == curr)
                i->ready_packets.tail = curr->prev;
            dhcp_release_spinlock(i->ready_packets.lock);

            size_t sz = curr->size;
            ethernet2_header* eth_hdr = curr->data;
            ip_header* ip_hdr = (ip_header*)(eth_hdr+1);
            sz -= sizeof(*eth_hdr);
            udp_header* udp_hdr = (udp_header*)(ip_hdr+1);
            sz -= sizeof(*ip_hdr);
            dhcp_header* dhcp_hdr = (dhcp_header*)(udp_hdr+1);
            bool res = false;
            dhcp_foreach_option(dhcp_hdr, sz, find_offer, &res);
            if (res)
            {
                offer_frame = curr;
                offer = dhcp_hdr;
                sz_offer = sz;
                offer_eth_hdr = eth_hdr;
                i->routing_info.server_ip_address = ip_hdr->src_address.addr;
                break;
            }

            curr = i->ready_packets.head;

        }
    }
    if (!offer_frame)
        return -1;

    // We have an offer!
    // Accept it.

    msg_type.payload[0] = DHCPREQUEST;
    dhcp_option_short requested_address = {.opcode=DHCP_OPT_REQUEST_IP,.length=4,};
    __builtin_memcpy(requested_address.payload, &offer->yiaddr, 4);
    dhcp_option_short server_identifier = {.opcode=DHCP_OPT_SERVER_IDENTIFIER,.length=4,};
    __builtin_memcpy(server_identifier.payload, &offer->siaddr, 4);
    // dhcp_option_short client_identifier = {.opcode=DHCP_OPT_CLIENT_IDENITIFER,.length=7,};
    // uint8_t client_identifier_type = 1;
    // __builtin_memcpy(client_identifier.payload, &client_identifier_type, 1);
    // __builtin_memcpy(client_identifier.payload+1, i->interface_mac, 6);
    frame request = {};
    interface_ready(i);
    dhcp_format_header(
        i,
        &request, 
        BOOTREQUEST, 
        be32toh(offer->xid),
        3,
        &msg_type,
        &requested_address,
        &server_identifier
    );
    ((dhcp_header*)request.data)->ciaddr = offer->yiaddr;
    ((dhcp_header*)request.data)->siaddr = offer->siaddr;
    __builtin_memset(dest_mac, 0xff, sizeof(dest_mac));
    transmit_udp_packet(
        i, 
        DHCP_SERVER_PORT, DHCP_CLIENT_PORT, 
        request.data, request.size, 
        (ip_addr){.addr=0xffffffff}, (ip_addr){.addr=0x0},
        &dest_mac
    );
    frame_unref(&request);

    // Wait for an DHCPACK or a DHCPNAK
    int spin = 0;
    const int timeout = 5 /* after 5 packets from the server we don't recognize, break */;
    uint8_t res[2] = {};
    i->routing_info.ip_address = offer->yiaddr;
    while (spin < timeout && !res[0])
    {
        for (frame* curr = i->ready_packets.head; curr && spin < timeout; )
        {
            dhcp_acquire_spinlock(i->ready_packets.lock);
            i->ready_packets.head = curr->next;
            if (curr->next)
                curr->next->prev = NULL;
            if (i->ready_packets.tail == curr)
                i->ready_packets.tail = curr->prev;
            dhcp_release_spinlock(i->ready_packets.lock);

            size_t sz = curr->size;
            ethernet2_header* eth_hdr = curr->data;
            ip_header* ip_hdr = (ip_header*)(eth_hdr+1);
            sz -= sizeof(*eth_hdr);
            udp_header* udp_hdr = (udp_header*)(ip_hdr+1);
            sz -= sizeof(*ip_hdr);
            dhcp_header* dhcp_hdr = (dhcp_header*)(udp_hdr+1);
            dhcp_foreach_option(dhcp_hdr, sz, is_ack_cb, &res);
            if (res[0])
            {
                // We got either a NAK or an ACK.
                break;
            }
            spin++;
        }
    }
    i->routing_info.ip_address = 0;
    if (!res[0])
    {
        dhcp_log("DHCP: Accepted an offer, but the DHCP server never sent an ACK/NAK back. Returning retry status.\n");
        i->routing_info.server_ip_address = 0;
        return -1;
    }
    if (res[1] == DHCPNAK)
    {
        dhcp_log("DHCP: Accepted an offer, but the DHCP server sent a NAK. Returning retry status.\n");
        i->routing_info.server_ip_address = 0;
        return -1;
    }

    interface_stop(i);

    dhcp_log("DHCP: Accepted an offer, and got an ACK.\nRegistering routing information.\n");

    i->routing_info.hdr = offer;
    frame_initialize(&i->routing_info.hdr_frame, offer_frame->data, offer_frame->size);
    i->routing_info.ip_address = offer->yiaddr;
    dhcp_foreach_option(offer, sz_offer, initalize_routing_info, i);
    dhcp_log("DHCP: Resolved IP address: %u.%u.%u.%u\n", 
        (be32toh(i->routing_info.ip_address) >> 24) & 0xff,
        (be32toh(i->routing_info.ip_address) >> 16) & 0xff,
        (be32toh(i->routing_info.ip_address) >> 8) & 0xff,
        (be32toh(i->routing_info.ip_address) >> 0) & 0xff
    );

    return 0;
}

void dhcp_ready(interface* i, frame* f, udp_header* udp_hdr)
{
    dhcp_header* hdr = (dhcp_header*)(udp_hdr + 1);
    if (be32toh(hdr->xid) != i->active_xid)
        return; // Not our packet :(
    
    frame* new = frame_alloc();
    frame_initialize(new, f->data, f->size);

    dhcp_acquire_spinlock(i->ready_packets.lock);
    // Queue the packet.
    if (i->ready_packets.tail)
        i->ready_packets.tail->next = new;
    if (!i->ready_packets.head)
        i->ready_packets.head = new;
    new->prev = i->ready_packets.tail;
    i->ready_packets.tail = new;
    dhcp_release_spinlock(i->ready_packets.lock);

    frame_unref(f);
}
