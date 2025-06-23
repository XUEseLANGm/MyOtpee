/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROTOCOLS_RPC_COMMON_HEADER_H
#define PROTOCOLS_RPC_COMMON_HEADER_H

#include <stdint.h>

/*
 * Defines an RPC request header that may be used for a packed-c serialization
 * of common RPC fields.  Different RPC protocols my carry some or all of these
 * fields in a protocol specific way.  If a particular protocol does't, this
 * structure provides a common definition that may be used.
 */
struct __attribute__ ((__packed__)) ts_rpc_req_hdr
{
    /*
     * A trustworthy identifier for the call originator.  Used for access control, applied
     * at the remote RPC interface.  This ID will have been added by an intermediary running
     * at a higher privilege level than the caller.  Example caller_ids could be the UID
     * or SELinux label associated with a calling process.  The caller_id may be supplemented
     * by a source identity from the messaging layer (e.g. the source partition ID).
     */
    uint32_t caller_id;

    /*
     * Identifies a particular RPC interface instance that is reachable at a messaging
     * endpoint.  Allows multiple services to be co-located at a single messaging endpoint.
     */
    uint16_t interface_id;

    /*
     * Identifies the requested operation to call.
     */
    uint16_t opcode;

    /*
     * Identifies the encoding scheme used to serialize request and response parameters.
     * It is the responsibility of the caller to specify an encoding that the destination
     * RPC interface can handle.  Must be set to a meaningful value, even if there are
     * no request parameters.  This is because response parameters will beb serialized
     * using the same encoding.
     */
    uint16_t encoding;

    /*
     * Specifies the length in bytes of the serialized parameters.
     */
    uint16_t param_len;
};

/*
 * Defines the coresponding response header, used for returning status and
 * any output parameters, serialized using the same encoding as specified in
 * the request header.
 */
struct __attribute__ ((__packed__)) ts_rpc_resp_hdr
{
    /*
     * Returns the RPC layer status.  Only if a value of TS_RPC_CALL_ACCEPTED
     * is returned should the opstatus value be consider.  The RPC status is
     * kept separate from the opstatus to allow a service specific status coding
     * namespace to coexist with the RPC status namespace.
     */
    int16_t rpc_status;

    /*
     * Returns the status of the requested operation.  The meaning of this status
     * code will be service specific.
     */
    int16_t op_status;

    /*
     * Specifies the length in bytes of the serialized parameters.
     */
    uint16_t param_len;
};

#endif /* PROTOCOLS_RPC_COMMON_HEADER_H */
