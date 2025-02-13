/*
 * src/main.c
 *
 * Copyright (c) 2025 Omar Berrow
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

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

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "%s interface\n", argv[0]);
        return 1;
    }
    return 0;
}
