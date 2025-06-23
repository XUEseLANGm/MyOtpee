/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include "raw_report_dump.h"

void raw_report_dump(const uint8_t *report, size_t len)
{
    size_t bytes_in_row = 0;
    size_t byte_count = 0;

    printf("\n*******report dump start (len: %ld)*******\n", len);

    while (byte_count < len) {

        printf("%02x", report[byte_count]);

        ++byte_count;
        ++bytes_in_row;

        if (bytes_in_row < 16) {

            printf(" ");
        }
        else {

            bytes_in_row = 0;
            printf("\n");
        }
    }

    if (bytes_in_row) printf("\n");

    printf("*******report dump end *******\n");
}
