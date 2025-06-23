/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_BLOCK_STORAGE_OPCODES_H
#define TS_BLOCK_STORAGE_OPCODES_H

/**
 * C/C++ definition of block storage service opcodes.
 */

#define TS_BLOCK_STORAGE_OPCODE_BASE                 (0x0100)
#define TS_BLOCK_STORAGE_OPCODE_GET_PARTITION_INFO   (TS_BLOCK_STORAGE_OPCODE_BASE + 1)
#define TS_BLOCK_STORAGE_OPCODE_OPEN                 (TS_BLOCK_STORAGE_OPCODE_BASE + 2)
#define TS_BLOCK_STORAGE_OPCODE_CLOSE                (TS_BLOCK_STORAGE_OPCODE_BASE + 3)
#define TS_BLOCK_STORAGE_OPCODE_READ                 (TS_BLOCK_STORAGE_OPCODE_BASE + 4)
#define TS_BLOCK_STORAGE_OPCODE_WRITE                (TS_BLOCK_STORAGE_OPCODE_BASE + 5)
#define TS_BLOCK_STORAGE_OPCODE_ERASE                (TS_BLOCK_STORAGE_OPCODE_BASE + 6)

#endif /* TS_BLOCK_STORAGE_OPCODES_H */
