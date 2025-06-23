/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_ATTESTATION_OPCODES_H
#define TS_ATTESTATION_OPCODES_H

/* C/C++ definition of attestation service opcodes
 */

#define TS_ATTESTATION_OPCODE_BASE                  (0x0100)

/* Report generation and retrieval operations */
#define TS_ATTESTATION_OPCODE_GET_TOKEN             (TS_ATTESTATION_OPCODE_BASE + 1)
#define TS_ATTESTATION_OPCODE_GET_TOKEN_SIZE        (TS_ATTESTATION_OPCODE_BASE + 2)

/* Provisioning operations */
#define TS_ATTESTATION_OPCODE_EXPORT_IAK_PUBLIC_KEY (TS_ATTESTATION_OPCODE_BASE + 3)
#define TS_ATTESTATION_OPCODE_IMPORT_IAK            (TS_ATTESTATION_OPCODE_BASE + 4)
#define TS_ATTESTATION_OPCODE_IAK_EXISTS            (TS_ATTESTATION_OPCODE_BASE + 5)

#endif /* TS_ATTESTATION_OPCODES_H */
