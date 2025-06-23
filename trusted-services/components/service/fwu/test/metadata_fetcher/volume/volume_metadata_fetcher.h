/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef VOLUME_METADATA_FETCHER_H
#define VOLUME_METADATA_FETCHER_H

#include "media/volume/block_volume/block_volume.h"
#include "service/fwu/test/metadata_fetcher/metadata_fetcher.h"

/*
 * A metadata_fetcher that fetches fwu metadata from a storage volume
 * that provides access to the disk partition used for fwu metadata.
 */
class volume_metadata_fetcher : public metadata_fetcher {
public:
	volume_metadata_fetcher(const struct uuid_octets *partition_guid,
				struct block_store *block_store);

	~volume_metadata_fetcher();

	void open(void);
	void close(void);
	void fetch(uint8_t *buf, size_t buf_size);

private:
	struct block_volume m_meta_block_volume;
	struct volume *m_meta_volume;
};

#endif /* VOLUME_METADATA_FETCHER_H */
