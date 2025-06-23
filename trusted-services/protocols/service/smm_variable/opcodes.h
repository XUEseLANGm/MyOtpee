/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_SMM_VARIABLE_OPCODES_H
#define TS_SMM_VARIABLE_OPCODES_H

/**
 * C/C++ definition of smm_variable service opcodes
 *
 * These defines are aligned to the SMM Variable definitions from EDK2. These versions
 * of these defines are maintained in the TS project to avoid a mandatory dependency
 * on the EDK2 project.
 */

#define SMM_VARIABLE_FUNCTION_GET_VARIABLE            1
#define SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME  2
#define SMM_VARIABLE_FUNCTION_SET_VARIABLE            3
#define SMM_VARIABLE_FUNCTION_QUERY_VARIABLE_INFO     4
#define SMM_VARIABLE_FUNCTION_READY_TO_BOOT           5
#define SMM_VARIABLE_FUNCTION_EXIT_BOOT_SERVICE       6

#define SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_SET  9
#define SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_GET  10
#define SMM_VARIABLE_FUNCTION_GET_PAYLOAD_SIZE        11

#endif /* TS_SMM_VARIABLE_OPCODES_H */
