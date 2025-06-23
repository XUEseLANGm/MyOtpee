/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPMB_FRONTEND_H_
#define RPMB_FRONTEND_H_

#include "components/service/rpmb/backend/rpmb_backend.h"
#include "components/rpc/common/caller/rpc_caller_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief RPMB platform interface
 *
 * It the interface for the necessary platform dependent functions:
 * * deriving RPMB key from hardware unique key
 * * get random nonce value
 * * calculate RPMB MAC value
 */
struct rpmb_platform_interface {
	/**
	 * \brief Device key from hardware unique key for creating the RPMB authentication key
	 *
	 * \param context[in]		Platform context
	 * \param data[in]		Key derivation data (i.e. salt)
	 * \param data_length[in]	Key derivation data length
	 * \param key[out]		Derived authentication key
	 * \param key_length[in]	Required authentication key length
	 * \return psa_status_t
	 */
	psa_status_t (*derive_key)(void *context, const uint8_t *data, size_t data_length,
				   uint8_t *key, size_t key_length);

	/**
	 * \brief Get random nonce value
	 *
	 * \param context[in]		Platform context
	 * \param nonce[out]		Generated nonce value
	 * \param nonce_length[in]	Nonce length
	 * \return psa_status_t
	 */
	psa_status_t (*get_nonce)(void *context, uint8_t *nonce, size_t nonce_length);

	/**
	 * \brief Calculate MAC field value
	 *
	 * \param context[in]		Platform context
	 * \param key[in]		Authentication key
	 * \param key_length[in]	Authentication key length
	 * \param frames[in]		Data frames
	 * \param frame_count[in]	Data frame count
	 * \param mac[out]		Calculated MAC value
	 * \param mac_length[in]	MAC value length
	 * \return psa_status_t
	 */
	psa_status_t (*calculate_mac)(void *context, const uint8_t *key, size_t key_length,
				      const struct rpmb_data_frame *frames, size_t frame_count,
				      uint8_t *mac, size_t mac_length);
};

/**
 * \brief RPMB platform
 *
 * Generic object for storing the RPMB platform interface and the implementation specific context.
 */
struct rpmb_platform {
	void *context;
	struct rpmb_platform_interface *interface;
};

/**
 * \brief RPMB frontend
 *
 * The RPMB frontend provides a high level read/write interface for accessing
 * the RPMB device and it does calls to the RPMB backend. This component
 * contains the main RPMB logic, including:
 * * Writing authentication key
 * * Handling the write counter
 * * Building and verifying RPMB data frames
 */
struct rpmb_frontend {
	struct rpmb_platform *platform;
	struct rpmb_backend *backend;
	uint32_t dev_id;
	bool initialized;
	size_t block_count;
	uint8_t key[RPMB_KEY_MAC_SIZE];
	uint32_t write_counter;
};

/**
 * \brief Create RPMB frontend
 *
 * This function only initializes the internal objects. It doesn't require the backend to be able
 * to access the RPMB hardware.
 *
 * \param context[in]	RPMB frontend context
 * \param platform[in]	RPMB platform
 * \param backend[in]	RPMB backend
 * \param dev_id[in]	Device ID
 * \return psa_status_t
 */
psa_status_t rpmb_frontend_create(struct rpmb_frontend *context, struct rpmb_platform *platform,
				  struct rpmb_backend *backend, uint32_t dev_id);

/**
 * \brief Init RPMB frontend
 *
 * This function requires access to the RPMB hardware via the backend. It reads derives the
 * authentication key, reads the write counter and possibly writes the authentication key.
 *
 * \param context[in]	RPMB frontend context
 * \return psa_status_t
 */
psa_status_t rpmb_frontend_init(struct rpmb_frontend *context);

/**
 * \brief Destroy RPMB frontend
 *
 * \param context[in]	RPMB frontend context
 */
void rpmb_frontend_destroy(struct rpmb_frontend *context);

/**
 * \brief Query RPMB block size
 *
 * \param context[in]		RPMB frontend context
 * \param block_size[out]	Block size in bytes
 * \return psa_status_t
 */
psa_status_t rpmb_frontend_block_size(struct rpmb_frontend *context, size_t *block_size);

/**
 * \brief Query RPMB block count
 *
 * \param context[in]		RPMB frontend context
 * \param block_count[out]	Block count
 * \return psa_status_t
 */
psa_status_t rpmb_frontend_block_count(struct rpmb_frontend *context, size_t *block_count);

/**
 * \brief Write complete blocks to RPMB
 *
 * \param context[in]		RPMB frontend context
 * \param block_index[in]	Block index
 * \param data[in]		Data, its size must be [block count] * [block size]
 * \param block_count[in]	Block count
 * \return psa_status_t
 */
psa_status_t rpmb_frontend_write(struct rpmb_frontend *context, uint16_t block_index,
				 const uint8_t *data, size_t block_count);

/**
 * \brief Read complete blocks from RPMB
 *
 * \param context[in]		RPMB frontend context
 * \param block_index[in]	Block index
 * \param data[out]		Data, its size must be [block count] * [block size]
 * \param block_count[in]	Block count
 * \return psa_status_t
 */
psa_status_t rpmb_frontend_read(struct rpmb_frontend *context, uint16_t block_index,
				uint8_t *data, size_t block_count);

#ifdef __cplusplus
}
#endif

#endif /* RPMB_CLIENT_H_ */
