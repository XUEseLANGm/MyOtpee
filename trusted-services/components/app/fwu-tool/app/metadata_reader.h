/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FWU_METADATA_READER_H
#define FWU_METADATA_READER_H

#include <cstdint>
#include <cstddef>
#include <vector>

/*
 * A version specific metadata reader. Before using get methods to extract
 * metadata attributes, is_supported() should be called to verify that the
 * input metadata version is supported.
 */
class metadata_version_specific_reader {
public:
	virtual ~metadata_version_specific_reader()
	{
	}

	virtual bool is_supported(const uint8_t *buf, size_t data_len) const = 0;

	virtual void get_version(const uint8_t *buf, size_t data_len,
				 unsigned int &version) const = 0;

	virtual void get_active_index(const uint8_t *buf, size_t data_len,
				      unsigned int &active_index) const = 0;
};

/*
 * A singleton that provides a common interface for reading fwu metadata.
 * The caller doesn't need to worry about the version of metadata being used.
 */
class metadata_reader {
public:
	static metadata_reader *instance();
	~metadata_reader();

	void register_reader(metadata_version_specific_reader *reader);

	int get_boot_info(unsigned int &active_index, unsigned int &metadata_version) const;

private:
	metadata_reader();

	std::vector<metadata_version_specific_reader *> registered_readers;
};

#endif /* FWU_METADATA_READER_H */
