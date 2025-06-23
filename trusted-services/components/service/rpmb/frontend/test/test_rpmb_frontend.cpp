/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>
#include "../rpmb_frontend.h"
#include "../platform/mock/rpmb_platform_mock.h"
#include "../../backend/mock/rpmb_backend_mock.h"
#include <string.h>

TEST_GROUP(rpmb_frontend) {
	TEST_SETUP()
	{
		psa_status_t status = PSA_ERROR_GENERIC_ERROR;

		platform = rpmb_platform_mock_init(&platform_mock);
		CHECK(platform != NULL);
		backend = rpmb_backend_mock_init(&backend_mock);
		CHECK(backend != NULL);
		status = rpmb_frontend_create(&frontend, platform, backend, dev_id);
		LONGS_EQUAL(PSA_SUCCESS, status);
	}

	TEST_TEARDOWN()
	{
		rpmb_frontend_destroy(&frontend);
		rpmb_backend_mock_deinit(&backend_mock);
		rpmb_platform_mock_deinit(&platform_mock);

		mock().checkExpectations();
		mock().clear();
	}

	void init_data_frame(struct rpmb_data_frame *frame, uint16_t address, uint16_t block_count,
			     uint16_t msg_type, const uint8_t *data, const uint8_t *nonce)
	{
		frame->address[0] = (address >> 8) & 0xff;
		frame->address[1] = address & 0xff;
		frame->block_count[0] = (block_count >> 8) & 0xff;
		frame->block_count[1] = block_count & 0xff;
		frame->msg_type[0] = (msg_type >> 8) & 0xff;
		frame->msg_type[1] = msg_type & 0xff;

		if (data)
			memcpy(frame->data, data, sizeof(frame->data));

		if (nonce)
			memcpy(frame->nonce, nonce, sizeof(frame->nonce));
	}

	void init()
	{
		psa_status_t status = PSA_ERROR_GENERIC_ERROR;
		struct rpmb_data_frame request = { 0 };
		struct rpmb_data_frame response = { 0 };

		size_t response_count = 1;

		rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
		rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid),
						     key, sizeof(key), PSA_SUCCESS);
		rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);

		memcpy(request.nonce, nonce, sizeof(request.nonce));
		request.msg_type[0] = 0x00;
		request.msg_type[1] = 0x02;
		memcpy(response.nonce, nonce, sizeof(response.nonce));
		memcpy(response.key_mac, mac, sizeof(response.key_mac));
		response.msg_type[0] = 0x02;
		response.msg_type[1] = 0x00;
		rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
						&response_count, PSA_SUCCESS);
		rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1,
							mac, sizeof(mac), PSA_SUCCESS);

		status = rpmb_frontend_init(&frontend);
		LONGS_EQUAL(PSA_SUCCESS, status);
	}

	struct rpmb_frontend frontend;
	struct rpmb_platform *platform;
	struct rpmb_platform_mock platform_mock;
	struct rpmb_backend *backend;
	struct rpmb_backend_mock backend_mock;
	const uint32_t dev_id = 1;
	const struct rpmb_dev_info dev_info = {
		.cid = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00},
		.rpmb_size_mult = 16
	};
	const uint8_t key[RPMB_KEY_MAC_SIZE] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
		0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0 };

	const uint8_t nonce[RPMB_NONCE_SIZE] = {
		0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
		0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa
	};
	const uint8_t mac[RPMB_KEY_MAC_SIZE] = {
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
		0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70 };
};

TEST(rpmb_frontend, create_null)
{
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_create(NULL, platform, backend, 0));
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_create(&frontend, NULL, backend, 0));
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_create(&frontend, platform, NULL, 0));
}

TEST(rpmb_frontend, init_get_dev_info_fail)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_dev_info dev_info = { 0 };

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info,
					      PSA_ERROR_COMMUNICATION_FAILURE);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_COMMUNICATION_FAILURE, status);
}

TEST(rpmb_frontend, init_zero_mult)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_dev_info dev_info = { 0 }; /* size_mult is zero */

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, status);
}

TEST(rpmb_frontend, init_derive_key_fail)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
	rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid), key,
					     sizeof(key), PSA_ERROR_BAD_STATE);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_BAD_STATE, status);
}

TEST(rpmb_frontend, init_get_nonce_fail)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
	rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid), key,
					     sizeof(key), PSA_SUCCESS);
	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_ERROR_BAD_STATE);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_BAD_STATE, status);
}

TEST(rpmb_frontend, init_read_write_counter_fail)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_data_frame request = { 0 };

	size_t response_count = 1;

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
	rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid), key,
					     sizeof(key), PSA_SUCCESS);
	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);

	memcpy(request.nonce, nonce, sizeof(request.nonce));
	request.msg_type[0] = 0x00;
	request.msg_type[1] = 0x02;
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &request, 1,
					      &response_count, PSA_ERROR_BAD_STATE);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_BAD_STATE, status);
}

TEST(rpmb_frontend, init_read_write_counter_invalid_result)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };

	size_t response_count = 1;

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
	rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid), key,
					     sizeof(key), PSA_SUCCESS);
	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);

	memcpy(request.nonce, nonce, sizeof(request.nonce));
	request.msg_type[0] = 0x00;
	request.msg_type[1] = 0x02;
	response.op_result[0] = 0xff;
	response.op_result[1] = 0xff;
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_count, PSA_SUCCESS);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_STORAGE_FAILURE, status);
}

TEST(rpmb_frontend, init_read_write_counter_invalid_type)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };

	size_t response_count = 1;

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
	rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid), key,
					     sizeof(key), PSA_SUCCESS);
	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);

	memcpy(request.nonce, nonce, sizeof(request.nonce));
	request.msg_type[0] = 0x00;
	request.msg_type[1] = 0x02;
	response.msg_type[0] = 0xff;
	response.msg_type[1] = 0xff;
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_count, PSA_SUCCESS);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_STORAGE_FAILURE, status);
}

TEST(rpmb_frontend, init_read_write_counter_invalid_nonce)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };

	size_t response_count = 1;

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
	rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid), key,
					     sizeof(key), PSA_SUCCESS);
	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);

	memcpy(request.nonce, nonce, sizeof(request.nonce));
	request.msg_type[0] = 0x00;
	request.msg_type[1] = 0x02;
	response.msg_type[0] = 0x02;
	response.msg_type[1] = 0x00;
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_count, PSA_SUCCESS);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_STORAGE_FAILURE, status);
}

TEST(rpmb_frontend, init_read_write_counter_calculate_mac_fail)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };

	size_t response_count = 1;

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
	rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid), key,
					     sizeof(key), PSA_SUCCESS);
	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);

	memcpy(request.nonce, nonce, sizeof(request.nonce));
	request.msg_type[0] = 0x00;
	request.msg_type[1] = 0x02;
	memcpy(response.nonce, nonce, sizeof(response.nonce));
	response.msg_type[0] = 0x02;
	response.msg_type[1] = 0x00;
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_ERROR_BAD_STATE);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_BAD_STATE, status);
}

TEST(rpmb_frontend, init_read_write_counter_invalid_mac)
{
	psa_status_t status = PSA_ERROR_GENERIC_ERROR;
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };

	size_t response_count = 1;

	rpmb_backend_mock_expect_get_dev_info(backend, dev_id, &dev_info, PSA_SUCCESS);
	rpmb_platform_mock_expect_derive_key(platform, dev_info.cid, sizeof(dev_info.cid), key,
					     sizeof(key), PSA_SUCCESS);
	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);

	memcpy(request.nonce, nonce, sizeof(request.nonce));
	request.msg_type[0] = 0x00;
	request.msg_type[1] = 0x02;
	memcpy(response.nonce, nonce, sizeof(response.nonce));
	response.msg_type[0] = 0x02;
	response.msg_type[1] = 0x00;
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	status = rpmb_frontend_init(&frontend);
	LONGS_EQUAL(PSA_ERROR_STORAGE_FAILURE, status);
}

TEST(rpmb_frontend, init_success)
{
	init();
}

TEST(rpmb_frontend, block_size)
{
	size_t block_size = 0;

	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_block_size(&frontend, &block_size));
	UNSIGNED_LONGS_EQUAL(256, block_size);
}

TEST(rpmb_frontend, block_count)
{
	size_t block_count = 0;

	LONGS_EQUAL(PSA_ERROR_BAD_STATE, rpmb_frontend_block_count(&frontend, &block_count));

	init();
	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_block_count(&frontend, &block_count));

	const size_t rpmb_mult_unit = 128 * 1024; /* The RPMB size unit is 128kB */
	const size_t rpmb_block_size = 256;
	const size_t expected_block_count =
		rpmb_mult_unit * dev_info.rpmb_size_mult / rpmb_block_size;

	UNSIGNED_LONGS_EQUAL(expected_block_count, block_count);
}

TEST(rpmb_frontend, write_null_context)
{
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_write(NULL, 0, NULL, 0));
}

TEST(rpmb_frontend, write_not_initialized)
{
	LONGS_EQUAL(PSA_ERROR_BAD_STATE, rpmb_frontend_write(&frontend, 0, NULL, 0));
}

TEST(rpmb_frontend, write_invalid_range)
{
	size_t block_count = 0;

	init();
	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_block_count(&frontend, &block_count));

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
		    rpmb_frontend_write(&frontend, block_count, NULL, 1));
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
		    rpmb_frontend_write(&frontend, block_count - 1, NULL, 2));
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
		    rpmb_frontend_write(&frontend, 1, NULL, block_count));
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
		    rpmb_frontend_write(&frontend, block_count - 1, NULL, SIZE_MAX));
}

TEST(rpmb_frontend, write_zero_size)
{
	init();

	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_write(&frontend, 0, NULL, 0));
}

TEST(rpmb_frontend, write_calculate_mac_fail)
{
	struct rpmb_data_frame request = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };

	init();

	memset(data, 0x5a, sizeof(data));
	init_data_frame(&request, 0x0001, 0x0001, 0x0003, data, NULL);

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &request, 1, mac,
						sizeof(mac), PSA_ERROR_STORAGE_FAILURE);

	LONGS_EQUAL(PSA_ERROR_STORAGE_FAILURE, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_data_request_fail)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 0;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_ERROR_STORAGE_FAILURE);

	LONGS_EQUAL(PSA_ERROR_STORAGE_FAILURE, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_response_count_fail)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 0;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INSUFFICIENT_DATA, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_mac_calc_fail)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_ERROR_BAD_STATE);

	LONGS_EQUAL(PSA_ERROR_BAD_STATE, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_mac_check_fail)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_SIGNATURE, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_invalid_write_counter)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	response.write_counter[0] = 0xff;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_invalid_address)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	response.write_counter[3] = 0x01;
	response.address[0] = 0xff;
	response.address[1] = 0x00;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_invalid_result)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	response.write_counter[3] = 0x01;
	response.address[0] = 0x00;
	response.address[1] = 0x01;
	response.op_result[0] = 0xff;
	response.op_result[1] = 0xff;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_invalid_msg_type)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	response.write_counter[3] = 0x01;
	response.address[0] = 0x00;
	response.address[1] = 0x01;
	response.op_result[0] = 0x00;
	response.op_result[1] = 0x00;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write)
{
	struct rpmb_data_frame mac_calc_request = { 0 };
	struct rpmb_data_frame request[2] = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	memset(data, 0x5a, sizeof(data));

	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request, &request[0], sizeof(mac_calc_request));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	init_data_frame(&response, 0x0001, 0, 0x0300, NULL, NULL);
	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	response.write_counter[3] = 0x01;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request, 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, request, 2, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_write(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, write_two_blocks)
{
	struct rpmb_data_frame mac_calc_request[2] = { 0 };
	struct rpmb_data_frame request[4] = { 0 };
	struct rpmb_data_frame response[2] = { 0 };
	uint8_t data[RPMB_DATA_SIZE * 2] = { 0 };
	size_t response_frame_count = 1;

	init();

	memset(data, 0x5a, RPMB_DATA_SIZE);
	memset(data + RPMB_DATA_SIZE, 0x1b, RPMB_DATA_SIZE);

	/* Block 1 */
	/* The write counter is zero at this point */
	init_data_frame(&request[0], 0x0001, 0x0001, 0x0003, data, NULL);
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request[0], &request[0], sizeof(mac_calc_request[0]));
	memcpy(request[0].key_mac, mac, sizeof(request[0].key_mac));

	request[1].msg_type[0] = 0x00;
	request[1].msg_type[1] = 0x05;

	/* Block 2 */
	init_data_frame(&request[2], 0x0002, 0x0001, 0x0003, data + RPMB_DATA_SIZE, NULL);
	request[2].write_counter[3] = 0x01;
	/* Save request without mac for the calculate_mac call */
	memcpy(&mac_calc_request[1], &request[2], sizeof(mac_calc_request[1]));
	memcpy(request[2].key_mac, mac, sizeof(request[2].key_mac));

	request[3].msg_type[0] = 0x00;
	request[3].msg_type[1] = 0x05;

	/* Response 1  */
	memcpy(response[0].key_mac, mac, sizeof(response[0].key_mac));
	init_data_frame(&response[0], 0x0001, 0, 0x0300, NULL, NULL);
	response[0].write_counter[3] = 0x01;

	/* Response 2 */
	memcpy(response[1].key_mac, mac, sizeof(response[1].key_mac));
	init_data_frame(&response[1], 0x0002, 0, 0x0300, NULL, NULL);
	response[1].write_counter[3] = 0x02;

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request[0], 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request[0], 2, &response[0], 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response[0], 1, mac,
						sizeof(mac), PSA_SUCCESS);

	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &mac_calc_request[1], 1,
						mac, sizeof(mac), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request[2], 2, &response[1], 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response[1], 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_write(&frontend, 1, data, 2));
}



TEST(rpmb_frontend, read_null_context)
{
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_read(NULL, 0, NULL, 0));
}

TEST(rpmb_frontend, read_not_initialized)
{
	LONGS_EQUAL(PSA_ERROR_BAD_STATE, rpmb_frontend_read(&frontend, 0, NULL, 0));
}

TEST(rpmb_frontend, read_invalid_range)
{
	size_t block_count = 0;

	init();
	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_block_count(&frontend, &block_count));

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
		    rpmb_frontend_read(&frontend, block_count, NULL, 1));
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
		    rpmb_frontend_read(&frontend, block_count - 1, NULL, 2));
	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT,
		    rpmb_frontend_read(&frontend, block_count - 1, NULL, SIZE_MAX));
}

TEST(rpmb_frontend, read_zero_size)
{
	init();

	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_read(&frontend, 0, NULL, 0));
}

TEST(rpmb_frontend, read_get_nonce_fail)
{
	init();

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_ERROR_BAD_STATE);

	LONGS_EQUAL(PSA_ERROR_BAD_STATE, rpmb_frontend_read(&frontend, 1, NULL, 1));
}

TEST(rpmb_frontend, read_data_request_fail)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 0;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_ERROR_STORAGE_FAILURE);

	LONGS_EQUAL(PSA_ERROR_STORAGE_FAILURE, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read_response_count_fail)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 0;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INSUFFICIENT_DATA, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read_mac_calc_fail)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_ERROR_BAD_STATE);

	LONGS_EQUAL(PSA_ERROR_BAD_STATE, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read_mac_check_fail)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_SIGNATURE, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read_nonce_check_fail)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	memcpy(response.key_mac, mac, sizeof(response.key_mac));

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_SIGNATURE, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read_invalid_block_address)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	memcpy(response.nonce, nonce, sizeof(response.nonce));
	response.address[0] = 0xff;
	response.address[1] = 0xff;

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read_invalid_block_count)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	init_data_frame(&response, 0x0001, 0xffff, 0, NULL, nonce);

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read_invalid_result)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	init_data_frame(&response, 0x0001, 0x0001, 0, NULL, nonce);
	response.op_result[0] = 0xff;
	response.op_result[1] = 0xff;

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read_invalid_type)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	init_data_frame(&response, 0x0001, 0x0001, 0xffff, NULL, nonce);
	response.op_result[0] = 0x00;
	response.op_result[1] = 0x00;

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_ERROR_INVALID_ARGUMENT, rpmb_frontend_read(&frontend, 1, data, 1));
}

TEST(rpmb_frontend, read)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response = { 0 };
	uint8_t expected_data[RPMB_DATA_SIZE] = { 0 };
	uint8_t data[RPMB_DATA_SIZE] = { 0 };
	size_t response_frame_count = 1;

	init();

	init_data_frame(&request, 0x0001, 0x0001, 0x0004, NULL, nonce);

	memset(expected_data, 0x5a, sizeof(expected_data));

	memcpy(response.key_mac, mac, sizeof(response.key_mac));
	memcpy(response.data, expected_data, sizeof(response.data));
	init_data_frame(&response, 0x0001, 0x0001, 0x0400, NULL, nonce);
	response.op_result[0] = 0x00;
	response.op_result[1] = 0x00;

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, &response, 1,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), &response, 1, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_read(&frontend, 1, data, 1));
	MEMCMP_EQUAL(expected_data, data, sizeof(expected_data));
}

TEST(rpmb_frontend, read_two_blocks)
{
	struct rpmb_data_frame request = { 0 };
	struct rpmb_data_frame response[2] = { 0 };
	uint8_t expected_data[RPMB_DATA_SIZE * 2] = { 0 };
	uint8_t data[RPMB_DATA_SIZE * 2] = { 0 };
	size_t response_frame_count = 2;

	init();

	memset(expected_data, 0x5a, RPMB_DATA_SIZE);
	memset(expected_data + RPMB_DATA_SIZE, 0x1b, RPMB_DATA_SIZE);

	init_data_frame(&request, 0x0001, 0x0002, 0x0004, NULL, nonce);

	memcpy(response[0].key_mac, mac, sizeof(response[0].key_mac));
	memcpy(response[0].data, expected_data, sizeof(response[0].data));
	init_data_frame(&response[0], 0x0001, 0x0002, 0x0400, NULL, nonce);
	response[0].op_result[0] = 0x00;
	response[0].op_result[1] = 0x00;

	memcpy(response[1].key_mac, mac, sizeof(response[1].key_mac));
	memcpy(response[1].data, expected_data + RPMB_DATA_SIZE, sizeof(response[1].data));
	init_data_frame(&response[1], 0x0001, 0x0002, 0x0400, NULL, nonce);
	response[1].op_result[0] = 0x00;
	response[1].op_result[1] = 0x00;

	rpmb_platform_mock_expect_get_nonce(platform, nonce, sizeof(nonce), PSA_SUCCESS);
	rpmb_backend_mock_expect_data_request(backend, dev_id, &request, 1, response, 2,
					      &response_frame_count, PSA_SUCCESS);
	rpmb_platform_mock_expect_calculate_mac(platform, key, sizeof(key), response, 2, mac,
						sizeof(mac), PSA_SUCCESS);

	LONGS_EQUAL(PSA_SUCCESS, rpmb_frontend_read(&frontend, 1, data, 2));
	MEMCMP_EQUAL(expected_data, data, sizeof(expected_data));
}

