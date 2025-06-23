/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_BACKEND_H_
#define RPMB_BACKEND_H_

#include "psa/error.h"
#include "compiler.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief RPMB request/response message types
 *
 * Defined in eMMC 4.5 (JESD84-B51) standard's Table 18.
 */
#define RPMB_REQ_TYPE_AUTHENTICATION_KEY_WRITE	(0x0001)
#define RPMB_REQ_TYPE_READ_WRITE_COUNTER	(0x0002)
#define RPMB_REQ_TYPE_AUTHENTICATED_DATA_WRITE	(0x0003)
#define RPMB_REQ_TYPE_AUTHENTICATED_DATA_READ	(0x0004)
#define RPMB_REQ_TYPE_RESULT_READ_REQUEST	(0x0005)
#define RPMB_REQ_TYPE_DEVICE_CONFIG_WRITE	(0x0006)
#define RPMB_REQ_TYPE_DEVICE_CONFIG_READ	(0x0007)

#define RPMB_RESP_TYPE_AUTHENTICATION_KEY_WRITE	(0x0100)
#define RPMB_RESP_TYPE_READ_WRITE_COUNTER	(0x0200)
#define RPMB_RESP_TYPE_AUTHENTICATED_DATA_WRITE	(0x0300)
#define RPMB_RESP_TYPE_AUTHENTICATED_DATA_READ	(0x0400)
#define RPMB_RESP_TYPE_DEVICE_CONFIG_WRITE	(0x0600)
#define RPMB_RESP_TYPE_DEVICE_CONFIG_READ	(0x0700)

/**
 * \brief RPMB operation results
 *
 * Defined in eMMC 4.5 (JESD84-B51) standard's Table 20.
 */
#define RPMB_RES_OK			(0x0000)
#define RPMB_RES_GENERAL_FAILURE	(0x0001)
#define RPMB_RES_AUTHENTICATION_FAILURE	(0x0002)
#define RPMB_RES_COUNTER_FAILURE	(0x0003)
#define RPMB_RES_ADDRESS_FAILURE	(0x0004)
#define RPMB_RES_WRITE_FAILURE		(0x0005)
#define RPMB_RES_READ_FAILURE		(0x0006)
#define RPMB_RES_KEY_NOT_PROGRAMMED	(0x0007)

#define RPMB_RES_COUNTER_EXPIRED	(0x0080)

/**
 * \brief Additional RPMB related definitions
 */
#define RPMB_EMMC_CID_SIZE		(16)
#define RPMB_CID_PRODUCT_REVISION	(9)
#define RPMB_CID_CRC7			(15)
#define RPMB_STUFF_DATA_SIZE		(196)
#define RPMB_KEY_MAC_SIZE		(32)
#define RPMB_DATA_SIZE			(256)
#define RPMB_NONCE_SIZE			(16)
#define RPMB_SIZE_MULT_UNIT		(128 * 1024)

/**
 * \brief RPMB device info
 *
 * The RPMB device info structure contains the Device Identification (CID) and RPMB_SIZE_MULT
 * registers' value. The CID value is unique to each RPMB device and it can be involved into the
 * authentication key generation process. The RPMB_SIZE_MULT value indicates the size of the RPMB
 * in 128kB units.
 */
struct rpmb_dev_info {
	uint8_t cid[RPMB_EMMC_CID_SIZE];
	uint8_t rpmb_size_mult;
} __packed;

/**
 * \brief RPMB data frame
 *
 * Defined in eMMC 4.5 (JESD84-B51) standard's Table 17.
 */
struct rpmb_data_frame {
	uint8_t stuff_bytes[RPMB_STUFF_DATA_SIZE];
	uint8_t key_mac[RPMB_KEY_MAC_SIZE];
	uint8_t data[RPMB_DATA_SIZE];
	uint8_t nonce[RPMB_NONCE_SIZE];
	uint8_t write_counter[4];
	uint8_t address[2];
	uint8_t block_count[2];
	uint8_t op_result[2];
	uint8_t msg_type[2];
} __packed;

/**
 * \brief RPMB backend interface
 *
 * The structure defines the function interface that the backend has to implement in order to
 * provide hardware access to the RPMB device.
 */
struct rpmb_backend_interface {
	psa_status_t (*get_dev_info)(void *context, uint32_t dev_id,
				     struct rpmb_dev_info *dev_info);

	psa_status_t (*data_request)(void *context, uint32_t dev_id,
				     const struct rpmb_data_frame *request_frames,
				     size_t request_frame_count,
				     struct rpmb_data_frame *response_frames,
				     size_t *response_frame_count);
};

/**
 * \brief RPMB backend
 *
 * Generic object for storing the RPMB backend interface and the implementation specific context.
 */
struct rpmb_backend {
	void *context;
	const struct rpmb_backend_interface *interface;
};

/**
 * \brief Query RPMB device info from the device
 *
 * \return Pointer to the base block_store or NULL on failure
 * \param[in] instance	RPMB backend instance
 * \param[in] dev_id	RPMB device ID
 * \param[out] dev_info	Device info
 * \return psa_status_t
 */
psa_status_t rpmb_backend_get_dev_info(struct rpmb_backend *instance, uint32_t dev_id,
				       struct rpmb_dev_info *dev_info);

/**
 * \brief Write and read data frames into and from the RPMB device.
 *
 * \param[in] instance			RPMB backend instance
 * \param[in] dev_id			RPMB device ID
 * \param[in] request_frames		Request data frames
 * \param[in] request_frame_count	Request data frame count
 * \param[out] response_frames		Response data frames
 * \param[inout] response_frame_count	in: maximal response data frame count, out: actual response
 *					data frame count
 * \return psa_status_t
 */
psa_status_t rpmb_backend_data_request(struct rpmb_backend *instance, uint32_t dev_id,
				       const struct rpmb_data_frame *request_frames,
				       size_t request_frame_count,
				       struct rpmb_data_frame *response_frames,
				       size_t *response_frame_count);

#ifdef __cplusplus
}
#endif

#endif /* RPMB_BACKEND_H_ */
