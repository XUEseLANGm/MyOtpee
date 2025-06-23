/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <rpc/common/protobuf/status.pb.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <CppUTest/TestHarness.h>

/*
 * Check alignment of RPC status protocol values for different protocol
 * definition schemes.
 */
TEST_GROUP(RpcStatusProtocolChecks) {

};

TEST(RpcStatusProtocolChecks, checkProtobufRpcStatusCodes) {

    /*
     * Check alignment between packed-c and protobuf rpc status codes
     */
    LONGS_EQUAL(TS_RPC_CALL_ACCEPTED,                       ts_rpc_Status_CALL_ACCEPTED);
    LONGS_EQUAL(TS_RPC_ERROR_EP_DOES_NOT_EXIT,              ts_rpc_Status_ERROR_EP_DOES_NOT_EXIT);
    LONGS_EQUAL(TS_RPC_ERROR_INVALID_OPCODE,                ts_rpc_Status_ERROR_INVALID_OPCODE);
    LONGS_EQUAL(TS_RPC_ERROR_SERIALIZATION_NOT_SUPPORTED,   ts_rpc_Status_ERROR_SERIALIZATION_NOT_SUPPORTED);
    LONGS_EQUAL(TS_RPC_ERROR_INVALID_REQ_BODY,              ts_rpc_Status_ERROR_INVALID_REQ_BODY);
    LONGS_EQUAL(TS_RPC_ERROR_INVALID_RESP_BODY,             ts_rpc_Status_ERROR_INVALID_RESP_BODY);
    LONGS_EQUAL(TS_RPC_ERROR_RESOURCE_FAILURE,              ts_rpc_Status_ERROR_RESOURCE_FAILURE);
    LONGS_EQUAL(TS_RPC_ERROR_NOT_READY,                     ts_rpc_Status_ERROR_NOT_READY);
    LONGS_EQUAL(TS_RPC_ERROR_INVALID_TRANSACTION,           ts_rpc_Status_ERROR_INVALID_TRANSACTION);
    LONGS_EQUAL(TS_RPC_ERROR_INTERNAL,                      ts_rpc_Status_ERROR_INTERNAL);
    LONGS_EQUAL(TS_RPC_ERROR_INVALID_PARAMETER,             ts_rpc_Status_ERROR_INVALID_PARAMETER);
}