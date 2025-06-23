/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LOGGING_CALLER_H
#define LOGGING_CALLER_H

#include <stdint.h>
#include <stdio.h>
#include <rpc_caller.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * An rpc_caller that logs call requests and responses to a file.
 * Can be stacked on top of another rpc_caller to allow call traffic to be
 * observed without interferring with the call flow.  Intended to be used
 * for debug and test purposes.
 **/
struct logging_caller
{
	struct rpc_caller rpc_caller;
	struct rpc_caller *attached_caller;
	uint32_t call_index;
	FILE *log_file;
};

/**
 * @brief      Initialises a logging_caller
 *
 * @param[in]  this_instance 	The RPC caller instance to initialize
 * @param[in]  log_file			Log to this file (assumed to be open)
 */
void logging_caller_init(
	struct logging_caller *this_instance,
	FILE *log_file);

/**
 * @brief      De-initialises a logging_caller
 *
 * @param[in]  this_instance 	The RPC caller instance to deinitialize
 */
void logging_caller_deinit(
	struct logging_caller *this_instance);

/**
 * @brief      Attach an rpc_caller to form a stack
 *
 * @param[in]  this_instance 	The RPC caller instance to initialize
 * @param[in]  attached_caller 	Stacked over this rpc_caller
 *
 * @return     The base rpc_caller that a client may use
 */
struct rpc_caller *logging_caller_attach(
	struct logging_caller *this_instance,
	struct rpc_caller *attached_caller);

#ifdef __cplusplus
}
#endif

#endif /* LOGGING_CALLER_H */
