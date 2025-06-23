/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COMMON_CRC32_H
#define COMMON_CRC32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initialize CRC32 to use HW acceleration if available
 */
void crc32_init(void);

/**
 * \brief Calculate a CRC32 over the provided data
 *
 * \param[in]	crc_prev	The starting CRC for previous data
 * \param[in]	buf		The buffer to calculate the CRC over
 * \param[in]	size		Number of bytes in the buffer
 *
 * \return	The calculated CRC32
 */
extern uint32_t (*crc32)(uint32_t crc_prev, const uint8_t *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* COMMON_CRC32_H */
