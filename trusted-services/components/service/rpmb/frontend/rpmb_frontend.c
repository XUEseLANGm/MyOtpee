/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rpmb_frontend.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

static void u32_to_rpmb_field(uint32_t u32, uint8_t *rpmb_field)
{
	rpmb_field[0] = (u32 >> 24) & 0xff;
	rpmb_field[1] = (u32 >> 16) & 0xff;
	rpmb_field[2] = (u32 >> 8) & 0xff;
	rpmb_field[3] = u32 & 0xff;
}

static uint32_t u32_from_rpmb_field(const uint8_t *rpmb_field)
{
	return (rpmb_field[0] << 24) | (rpmb_field[1] << 16) | (rpmb_field[2] << 8) | rpmb_field[3];
}

static void u16_to_rpmb_field(uint16_t u16, uint8_t *rpmb_field)
{
	rpmb_field[0] = (u16 >> 8) & 0xff;
	rpmb_field[1] = u16 & 0xff;
}

static uint16_t u16_from_rpmb_field(const uint8_t *rpmb_field)
{
	return (rpmb_field[0] << 8) | rpmb_field[1];
}

static inline psa_status_t rpmb_derive_key(struct rpmb_frontend *frontend, const uint8_t *data,
					   size_t data_length, uint8_t *key, size_t key_length)
{
	struct rpmb_platform *platform = frontend->platform;

	return platform->interface->derive_key(platform->context, data, data_length, key,
					       key_length);
}


static inline psa_status_t rpmb_get_nonce(struct rpmb_frontend *frontend, uint8_t *nonce,
					  size_t nonce_length)
{
	struct rpmb_platform *platform = frontend->platform;

	return platform->interface->get_nonce(platform->context, nonce, nonce_length);
}


static inline psa_status_t rpmb_calculate_mac(struct rpmb_frontend *frontend,
					      const struct rpmb_data_frame *frames,
					      size_t frame_count, uint8_t *mac)
{
	struct rpmb_platform *platform = frontend->platform;

	return platform->interface->calculate_mac(platform->context, frontend->key,
						  sizeof(frontend->key), frames, frame_count, mac,
						  RPMB_KEY_MAC_SIZE);
}

static psa_status_t rpmb_read_write_counter(struct rpmb_frontend *context)
{
	struct rpmb_data_frame frame = { 0 };
	size_t response_frame_count = 1;
	uint8_t nonce[RPMB_NONCE_SIZE] = { 0 };
	uint8_t mac[RPMB_KEY_MAC_SIZE] = { 0 };
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	uint16_t resp_type = 0;
	uint16_t op_result = RPMB_RES_GENERAL_FAILURE;

	status = rpmb_get_nonce(context, nonce, sizeof(nonce));
	if (status != PSA_SUCCESS)
		return status;

	/* Setting nonce and request type */
	memcpy(frame.nonce, nonce, sizeof(frame.nonce));
	u16_to_rpmb_field(RPMB_REQ_TYPE_READ_WRITE_COUNTER, frame.msg_type);

	status = rpmb_backend_data_request(context->backend, context->dev_id, &frame, 1,
					   &frame, &response_frame_count);
	if (status != PSA_SUCCESS)
		return status;

	/* Validate response type, result, nonce and MAC */
	op_result = u16_from_rpmb_field(frame.op_result);
	if (op_result != RPMB_RES_OK)
		return PSA_ERROR_STORAGE_FAILURE;

	resp_type = u16_from_rpmb_field(frame.msg_type);
	if (resp_type != RPMB_RESP_TYPE_READ_WRITE_COUNTER)
		return PSA_ERROR_STORAGE_FAILURE;

	if (memcmp(frame.nonce, nonce, sizeof(frame.nonce)) != 0)
		return PSA_ERROR_STORAGE_FAILURE;

	status = rpmb_calculate_mac(context, &frame, 1, mac);
	if (status != PSA_SUCCESS)
		return status;

	if (memcmp(frame.key_mac, mac, sizeof(frame.key_mac)) != 0)
		return PSA_ERROR_STORAGE_FAILURE;

	context->write_counter = u32_from_rpmb_field(frame.write_counter);

	return PSA_SUCCESS;
}

#if RPMB_WRITE_KEY
static bool rpmb_is_key_set(struct rpmb_frontend *context)
{
	return rpmb_read_write_counter(context) == PSA_SUCCESS;
}

static psa_status_t rpmb_write_key(struct rpmb_frontend *context)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_data_frame frames[2] = { 0 };
	size_t response_count = 0;
	uint16_t msg_type = 0;

	/* Authentication Key Data Packet */
	memcpy(frames[0].key_mac, context->key, sizeof(frames[0].key_mac));
	u16_to_rpmb_field(RPMB_REQ_TYPE_AUTHENTICATION_KEY_WRITE, frames[0].msg_type);

	/* Result Register Read Request Packet*/
	u16_to_rpmb_field(RPMB_REQ_TYPE_RESULT_READ_REQUEST, frames[1].msg_type);

	response_count = 1;
	status = rpmb_backend_data_request(context->backend, context->dev_id, frames, 2, frames,
					   &response_count);
	if (status != PSA_SUCCESS)
		return status;

	if (response_count != 1)
		return PSA_ERROR_INSUFFICIENT_DATA;

	/* Parse Response for Key Programming Result Request */
	msg_type = u16_from_rpmb_field(frames[0].msg_type);
	if (u16_from_rpmb_field(frames[0].op_result) != RPMB_RES_OK ||
	    msg_type != RPMB_RESP_TYPE_AUTHENTICATION_KEY_WRITE)
		return PSA_ERROR_STORAGE_FAILURE;

	return PSA_SUCCESS;
}
#endif /* RPMB_WRITE_KEY */

psa_status_t rpmb_frontend_create(struct rpmb_frontend *context, struct rpmb_platform *platform,
				  struct rpmb_backend *backend, uint32_t dev_id)
{
	if (!context || !platform || !backend)
		return PSA_ERROR_INVALID_ARGUMENT;

	*context = (struct rpmb_frontend){ 0 };

	context->platform = platform;
	context->backend = backend;
	context->dev_id = dev_id;

	return PSA_SUCCESS;
}

psa_status_t rpmb_frontend_init(struct rpmb_frontend *context)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_dev_info dev_info = { 0 };

	status = rpmb_backend_get_dev_info(context->backend, context->dev_id, &dev_info);
	if (status != PSA_SUCCESS)
		return status;

	if (!dev_info.rpmb_size_mult)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (MUL_OVERFLOW(dev_info.rpmb_size_mult, RPMB_SIZE_MULT_UNIT / RPMB_DATA_SIZE,
			 &context->block_count))
		return PSA_ERROR_INVALID_ARGUMENT;

	/* Mask product revision and CRC because it might change on eMMC FFU */
	dev_info.cid[RPMB_CID_PRODUCT_REVISION] = 0;
	dev_info.cid[RPMB_CID_CRC7] = 0;
	status = rpmb_derive_key(context, dev_info.cid, sizeof(dev_info.cid), context->key,
				 RPMB_KEY_MAC_SIZE);
	if (status != PSA_SUCCESS)
		return status;

#if RPMB_WRITE_KEY
	if (!rpmb_is_key_set(context)) {
		status = rpmb_write_key(context);
		if (status != PSA_SUCCESS)
			return status;
	}
#endif /* RPMB_WRITE_KEY */

	status = rpmb_read_write_counter(context);
	if (status != PSA_SUCCESS)
		return status;

	context->initialized = true;

	return PSA_SUCCESS;
}

void rpmb_frontend_destroy(struct rpmb_frontend *context)
{
	*context = (struct rpmb_frontend){ 0 };
}

psa_status_t rpmb_frontend_block_size(struct rpmb_frontend *context, size_t *block_size)
{
	*block_size = RPMB_DATA_SIZE;
	return PSA_SUCCESS;
}

psa_status_t rpmb_frontend_block_count(struct rpmb_frontend *context, size_t *block_count)
{
	if (!context->initialized)
		return PSA_ERROR_BAD_STATE;

	*block_count = context->block_count;
	return PSA_SUCCESS;
}

psa_status_t rpmb_frontend_write(struct rpmb_frontend *context, uint16_t block_index,
				 const uint8_t *data, size_t block_count)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_data_frame frames[2] = { 0 };
	uint8_t mac[RPMB_KEY_MAC_SIZE] = { 0 };
	size_t response_count = 0;
	uint32_t write_counter = 0;
	uint16_t op_result = 0;
	size_t last_block = 0;
	uint16_t msg_type = 0;
	uint16_t address = 0;
	uint16_t i = 0;

	if (!context)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (!context->initialized)
		return PSA_ERROR_BAD_STATE;

	/* Validating block range */
	if (block_index >= context->block_count ||
	    ADD_OVERFLOW(block_index, block_count, &last_block) ||
	    last_block > context->block_count)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (block_count == 0)
		return PSA_SUCCESS;

	for (i = 0; i < block_count; i++) {
		/* Program Data Packet */
		memset(frames, 0x00, sizeof(frames));
		memcpy(frames[0].data, &data[i * RPMB_DATA_SIZE], RPMB_DATA_SIZE);
		u32_to_rpmb_field(context->write_counter, frames[0].write_counter);
		u16_to_rpmb_field(block_index + i, frames[0].address);
		u16_to_rpmb_field(1, frames[0].block_count);
		u16_to_rpmb_field(RPMB_REQ_TYPE_AUTHENTICATED_DATA_WRITE, frames[0].msg_type);

		status = rpmb_calculate_mac(context, frames, 1, frames[0].key_mac);
		if (status != PSA_SUCCESS)
			return status;

		/* Result Register Read Request Packet */
		memset(&frames[1], 0x00, sizeof(frames[1]));
		u16_to_rpmb_field(RPMB_REQ_TYPE_RESULT_READ_REQUEST, frames[1].msg_type);

		/* Do the request to the backend */
		response_count = 1;
		status = rpmb_backend_data_request(context->backend, context->dev_id, frames,
						   ARRAY_SIZE(frames), frames, &response_count);
		if (status != PSA_SUCCESS)
			return status;

		if (response_count != 1)
			return PSA_ERROR_INSUFFICIENT_DATA;

		/* Parse Response for Data Programming Result Request */
		status = rpmb_calculate_mac(context, &frames[0], 1, mac);
		if (status != PSA_SUCCESS)
			return status;

		if (memcmp(frames[0].key_mac, mac, sizeof(mac)) != 0)
			return PSA_ERROR_INVALID_SIGNATURE;

		write_counter = u32_from_rpmb_field(frames[0].write_counter);
		if (write_counter != context->write_counter + 1)
			return PSA_ERROR_INVALID_ARGUMENT;

		address = u16_from_rpmb_field(frames[0].address);
		if (address != block_index + i)
			return PSA_ERROR_INVALID_ARGUMENT;

		op_result = u16_from_rpmb_field(frames[0].op_result);
		if (op_result != RPMB_RES_OK)
			return PSA_ERROR_INVALID_ARGUMENT;

		msg_type = u16_from_rpmb_field(frames[0].msg_type);
		if (msg_type != RPMB_RESP_TYPE_AUTHENTICATED_DATA_WRITE)
			return PSA_ERROR_INVALID_ARGUMENT;

		context->write_counter = write_counter;
	}

	return PSA_SUCCESS;

}

psa_status_t rpmb_frontend_read(struct rpmb_frontend *context, uint16_t block_index,
				uint8_t *data, size_t block_count)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	uint8_t mac[RPMB_KEY_MAC_SIZE] = { 0 };
	uint8_t nonce[RPMB_NONCE_SIZE] = { 0 };
	struct rpmb_data_frame *frames = NULL;
	size_t response_count = 0;
	size_t last_block = 0;
	uint16_t msg_type = 0;
	uint16_t i = 0;

	if (!context)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (!context->initialized)
		return PSA_ERROR_BAD_STATE;

	/* Validating block range */
	if (block_index >= context->block_count ||
	    ADD_OVERFLOW(block_index, block_count, &last_block) ||
	    last_block > context->block_count)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (block_count == 0)
		return PSA_SUCCESS;

	frames = (struct rpmb_data_frame *)calloc(block_count, sizeof(*frames));
	if (!frames)
		return PSA_ERROR_INSUFFICIENT_MEMORY;

	/* Data Read Request Initiation Packet */
	status = rpmb_get_nonce(context, nonce, sizeof(nonce));
	if (status != PSA_SUCCESS)
		goto err;

	memcpy(frames[0].nonce, nonce, sizeof(frames[0].nonce));
	u16_to_rpmb_field(block_index, frames[0].address);
	u16_to_rpmb_field(block_count, frames[0].block_count);
	u16_to_rpmb_field(RPMB_REQ_TYPE_AUTHENTICATED_DATA_READ, frames[0].msg_type);

	response_count = block_count;
	status = rpmb_backend_data_request(context->backend, context->dev_id, frames, 1, frames,
					   &response_count);
	if (status != PSA_SUCCESS)
		goto err;

	if (response_count != block_count) {
		status = PSA_ERROR_INSUFFICIENT_DATA;
		goto err;
	}

	status = rpmb_calculate_mac(context, frames, block_count, mac);
	if (status != PSA_SUCCESS)
		goto err;

	if (memcmp(mac, frames[block_count - 1].key_mac, sizeof(mac)) != 0) {
		status = PSA_ERROR_INVALID_SIGNATURE;
		goto err;
	}

	for (i = 0; i < block_count; i++) {
		/* Parse Read Data Packets */
		if (memcmp(frames[i].nonce, nonce, sizeof(nonce)) != 0) {
			status = PSA_ERROR_INVALID_SIGNATURE;
			goto err;
		}

		msg_type = u16_from_rpmb_field(frames[i].msg_type);
		if (u16_from_rpmb_field(frames[i].address) != block_index ||
		    u16_from_rpmb_field(frames[i].block_count) != block_count ||
		    u16_from_rpmb_field(frames[i].op_result) != RPMB_RES_OK ||
		    msg_type != RPMB_RESP_TYPE_AUTHENTICATED_DATA_READ) {
			status = PSA_ERROR_INVALID_ARGUMENT;
			goto err;
		}

		memcpy(&data[i * RPMB_DATA_SIZE], frames[i].data, RPMB_DATA_SIZE);
	}

err:
	free(frames);
	return status;
}
