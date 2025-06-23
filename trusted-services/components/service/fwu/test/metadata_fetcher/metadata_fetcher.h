/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef METADATA_FETCHER_H
#define METADATA_FETCHER_H

#include <cstddef>
#include <cstdint>

/*
 * The metadata_fetcher provides an interface for fetching the current
 * fwu metadata and writing it to a presented buffer. Different concrete
 * fetching methods can be used for alternative test configurations.
 */
class metadata_fetcher {
public:
	metadata_fetcher()
	{
	}

	virtual ~metadata_fetcher()
	{
	}

	virtual void open(void) = 0;
	virtual void close(void) = 0;
	virtual void fetch(uint8_t *buf, size_t buf_size) = 0;
};

#endif /* METADATA_FETCHER_H */
