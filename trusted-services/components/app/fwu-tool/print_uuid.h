/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef PRINT_UUID_H
#define PRINT_UUID_H

#include <cstdint>
#include <string>

std::string print_uuid(const uint8_t *uuid_octets);

#endif /* PRINT_UUID_H */
