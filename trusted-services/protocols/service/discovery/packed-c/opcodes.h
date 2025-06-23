/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_DISCOVERY_OPCODES_H
#define TS_DISCOVERY_OPCODES_H

/**
 * C/C++ definition of discovery service opcodes.
 *
 * Discovery service operations should be callable at all service
 * endpoints to support service discovery.
 */

#define TS_DISCOVERY_OPCODE_BASE                 (0x0000)
#define TS_DISCOVERY_OPCODE_GET_SERVICE_INFO     (TS_DISCOVERY_OPCODE_BASE + 1)
#define TS_DISCOVERY_OPCODE_GET_PROVIDER_INFO    (TS_DISCOVERY_OPCODE_BASE + 2)
#define TS_DISCOVERY_OPCODE_GET_SERVICE_CAPS     (TS_DISCOVERY_OPCODE_BASE + 3)

#endif /* TS_DISCOVERY_OPCODES_H */
