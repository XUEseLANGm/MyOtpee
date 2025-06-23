/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROTOCOLS_RPC_COMMON_ENCODING_H
#define PROTOCOLS_RPC_COMMON_ENCODING_H

/*
 * Encodings used for parameter serialization.
 */
enum
{
    /*
     * Packed-c encoding.  A lightweight serialization scheme with
     * C language definition files.
     */
    TS_RPC_ENCODING_PACKED_C        =  0,

    /*
     * Protocol Buffers serialization scheme with language independent
     * definition files.  Supports client code generation using definition
     * files.
     */
    TS_RPC_ENCODING_PROTOBUF        =  1,

    /*
     * The limit of known encodings.  As new encodings are added,
     * the limit value should be allowed to increase.  An RPC interface
     * that was built before a new encoding was added should safely
     * reject an unsupported encoding.
     */
    TS_RPC_ENCODING_LIMIT
};

#endif /* PROTOCOLS_RPC_COMMON_ENCODING_H */
