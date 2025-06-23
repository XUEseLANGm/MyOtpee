/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_PS_SERVICE_CONTEXT_H
#define STANDALONE_PS_SERVICE_CONTEXT_H

#include <service/locator/standalone/standalone_service_context.h>
#include <service/secure_storage/frontend/secure_storage_provider/secure_storage_provider.h>
#include <service/secure_storage/backend/secure_flash_store/flash/block_store_adapter/sfs_flash_block_store_adapter.h>
#include <service/block_storage/block_store/block_store.h>

class ps_service_context : public standalone_service_context
{
public:
	ps_service_context(const char *sn);
	virtual ~ps_service_context();

private:

	void do_init();
	void do_deinit();

	static const size_t MAX_NUM_FILES = 10;
	static const size_t MIN_FLASH_BLOCK_SIZE = 4096;

	struct secure_storage_provider m_storage_provider;
	struct sfs_flash_block_store_adapter m_sfs_flash_adapter;
	struct block_store *m_block_store;
};

#endif /* STANDALONE_PS_SERVICE_CONTEXT_H */
