/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PRETTY_REPORT_DUMP_H
#define PRETTY_REPORT_DUMP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Pretty print an attestation report
 */
int pretty_report_dump(const uint8_t *report, size_t len);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PRETTY_REPORT_DUMP_H */
