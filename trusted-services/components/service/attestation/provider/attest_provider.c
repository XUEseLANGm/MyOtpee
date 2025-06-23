/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "attest_provider.h"
#include "protocols/service/attestation/packed-c/opcodes.h"
#include "protocols/rpc/common/packed-c/status.h"
#include "service/attestation/key_mngr/attest_key_mngr.h"
#include "service/attestation/reporter/attest_report.h"
#include "psa/initial_attestation.h"
#include "attestation_uuid.h"
#include <stdlib.h>
#include <string.h>

/* Service request handlers */
static rpc_status_t get_token_handler(void *context, struct rpc_request *req);
static rpc_status_t get_token_size_handler(void *context, struct rpc_request *req);
static rpc_status_t export_iak_public_key_handler(void *context, struct rpc_request *req);
static rpc_status_t import_iak_handler(void *context, struct rpc_request *req);
static rpc_status_t iak_exists_handler(void *context, struct rpc_request *req);

/* Handler mapping table for service */
static const struct service_handler handler_table[] = {
	{TS_ATTESTATION_OPCODE_GET_TOKEN,               get_token_handler},
	{TS_ATTESTATION_OPCODE_GET_TOKEN_SIZE,          get_token_size_handler},
	{TS_ATTESTATION_OPCODE_EXPORT_IAK_PUBLIC_KEY,   export_iak_public_key_handler},
	{TS_ATTESTATION_OPCODE_IMPORT_IAK,              import_iak_handler},
	{TS_ATTESTATION_OPCODE_IAK_EXISTS,              iak_exists_handler}
};

struct rpc_service_interface *attest_provider_init(struct attest_provider *context)
{
	const struct rpc_uuid attest_service_uuid = { .uuid = TS_PSA_ATTESTATION_SERVICE_UUID };

	if (!context)
		return NULL;

	context->serializer = NULL;

	service_provider_init(&context->base_provider, context, &attest_service_uuid,
			      handler_table, sizeof(handler_table)/sizeof(struct service_handler));

	return service_provider_get_rpc_interface(&context->base_provider);
}

void attest_provider_deinit(struct attest_provider *context)
{
	(void)context;
}

void attest_provider_register_serializer(struct attest_provider *context,
					 const struct attest_provider_serializer *serializer)
{
	context->serializer = serializer;
}

static rpc_status_t get_token_handler(void *context, struct rpc_request *req)
{
	struct attest_provider *this_instance = (struct attest_provider *)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	uint8_t challenge[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64];
	size_t challenge_len = sizeof(challenge);
	const struct attest_provider_serializer *serializer = this_instance->serializer;
	const uint8_t *token = NULL;
	size_t token_size = 0;

	if (!serializer)
		return rpc_status;

	rpc_status = serializer->deserialize_get_token_req(&req->request, challenge,
							   &challenge_len);
	if (rpc_status != RPC_SUCCESS)
		return rpc_status;

	req->service_status = attest_report_create((int32_t)req->source_id, challenge,
						   challenge_len, &token, &token_size);

	if (req->service_status == PSA_SUCCESS)
		rpc_status = serializer->serialize_get_token_resp(&req->response, token,
								  token_size);

	attest_report_destroy(token);

	return rpc_status;
}

static rpc_status_t get_token_size_handler(void *context, struct rpc_request *req)
{
	struct attest_provider *this_instance = (struct attest_provider*)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	uint8_t challenge[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64];
	size_t challenge_len = sizeof(challenge);
	const struct attest_provider_serializer *serializer = this_instance->serializer;
	const uint8_t *token = NULL;
	size_t token_size = 0;

	memset(challenge, 0, sizeof(challenge));

	if (!serializer)
		return rpc_status;

	rpc_status = serializer->deserialize_get_token_size_req(&req->request, &challenge_len);
	if (rpc_status != RPC_SUCCESS)
		return rpc_status;

	req->service_status = attest_report_create((int32_t)req->source_id, challenge,
						   challenge_len, &token, &token_size);

	if (req->service_status == PSA_SUCCESS)
		rpc_status = serializer->serialize_get_token_size_resp(&req->response, token_size);

	attest_report_destroy(token);

	return rpc_status;
}

static rpc_status_t export_iak_public_key_handler(void *context, struct rpc_request *req)
{
	struct attest_provider *this_instance = (struct attest_provider *)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	const struct attest_provider_serializer *serializer = this_instance->serializer;
	size_t max_key_size = 0;
	uint8_t *key_buffer = NULL;
	size_t export_size = 0;

	if (!serializer)
		return rpc_status;

	max_key_size = attest_key_mngr_max_iak_export_size();
	key_buffer = malloc(max_key_size);

	if (!key_buffer)
		return rpc_status;

	req->service_status = attest_key_mngr_export_iak_public_key(key_buffer, max_key_size,
								    &export_size);

	rpc_status = RPC_SUCCESS;

	if (req->service_status == PSA_SUCCESS)
		rpc_status = serializer->serialize_export_iak_public_key_resp(
			&req->response, key_buffer, export_size);

	free(key_buffer);

	return rpc_status;
}

static rpc_status_t import_iak_handler(void *context, struct rpc_request *req)
{
	struct attest_provider *this_instance = (struct attest_provider *)context;
	rpc_status_t rpc_status = RPC_ERROR_INTERNAL;
	const struct attest_provider_serializer *serializer = this_instance->serializer;
	size_t key_data_len = 0;
	uint8_t *key_buffer = NULL;

	if (!serializer)
		return rpc_status;

	key_data_len = attest_key_mngr_max_iak_import_size();
	key_buffer = malloc(key_data_len);

	if (!key_buffer)
		return rpc_status;

	rpc_status = serializer->deserialize_import_iak_req(&req->request, key_buffer,
							    &key_data_len);

	if (rpc_status == RPC_SUCCESS)
		req->service_status = attest_key_mngr_import_iak(key_buffer, key_data_len);

	free(key_buffer);

	return rpc_status;
}

static rpc_status_t iak_exists_handler(void *context, struct rpc_request *req)
{
	(void)context;

	service_status_t opstatus = PSA_ERROR_DOES_NOT_EXIST;

	if (attest_key_mngr_iak_exists()) {

	   opstatus = PSA_SUCCESS;
	}

	req->service_status = opstatus;

	return RPC_SUCCESS;
}
