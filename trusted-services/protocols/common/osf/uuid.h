/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Common Open Software Foundation (OSF) standards-based definitions
 */

#ifndef COMMON_OSF_UUID_H
#define COMMON_OSF_UUID_H

/**
 * Octet length for standard binary encoded UUID in Big Endian byte order (see RFC4122)
 */
#define OSF_UUID_OCTET_LEN (16)

/**
 * Character length of a canonical form UUID string
 * e.g. 123e4567-e89b-12d3-a456-426614174000
 */
#define OSF_UUID_CANONICAL_FORM_LEN (36)

#endif /* COMMON_OSF_UUID_H */
