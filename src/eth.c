/*
 * src/eth.c
 *
 * Copyright (c) 2025 Omar Berrow
 */

#include <endian.h>
#include <stdint.h>
#include <stddef.h>

#include "eth.h"

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
    if (!i || !data || !sz || header_template)
        return 1;
    frame f = {};
    frame_initialize(&f, NULL, sizeof(ethernet2_header)+sz);
    __builtin_memcpy(f.data, header_template, sizeof(ethernet2_header));
    __builtin_memcpy(((char*)f.data)+sizeof(ethernet2_header), data, sz);
    i->write_frame(i, &f);
    frame_unref(&f);
    return 0;
}

void data_ready(void* user, interface* i, frame* f)
{
    (void)user;
    (void)i;
    (void)f;
    
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