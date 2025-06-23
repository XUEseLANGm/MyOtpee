/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_TEST_RUNNER_OPCODES_H
#define TS_TEST_RUNNER_OPCODES_H

/**
 *  C/C++ definition of test_runner service opcodes
 */

#define TS_TEST_RUNNER_OPCODE_BASE              (0x0100)
#define TS_TEST_RUNNER_OPCODE_RUN_TESTS         (TS_TEST_RUNNER_OPCODE_BASE + 1)
#define TS_TEST_RUNNER_OPCODE_LIST_TESTS        (TS_TEST_RUNNER_OPCODE_BASE + 2)

#endif /* TS_TEST_RUNNER_OPCODES_H */
