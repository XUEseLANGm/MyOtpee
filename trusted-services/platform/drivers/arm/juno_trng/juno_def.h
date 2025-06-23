/*
 * Copyright (c) 2014-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 *
 * Based on the the trustedfirmware-a file with the same name.  All but the
 * TRNG defines are stripped out.
 */

#ifndef JUNO_DEF_H
#define JUNO_DEF_H

#include <stdint.h>

/*******************************************************************************
 * TRNG related constants
 ******************************************************************************/
#define TRNG_NOUTPUTS	4
#define TRNG_STATUS	UINT32_C(0x10)
#define TRNG_INTMASK	UINT32_C(0x14)
#define TRNG_CONFIG	UINT32_C(0x18)
#define TRNG_CONTROL	UINT32_C(0x1C)
#define TRNG_NBYTES	16	/* Number of bytes generated per round. */



#endif /* JUNO_DEF_H */
