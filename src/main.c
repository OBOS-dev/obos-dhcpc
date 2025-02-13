/*
 * src/main.c
 *
 * Copyright (c) 2025 Omar Berrow
 */

#include <stdio.h>
#include <stdint.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "%s interface\n", argv[0]);
        return 1;
    }
    return 0;
}
