/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef METADATA_CHECKER_H
#define METADATA_CHECKER_H

#include <cstdint>

#include "service/fwu/test/metadata_fetcher/metadata_fetcher.h"

/*
 * Provides check methods for verifying that the state of fwu metadata is
 * as expected. To allow different metadata versions to be checked, some
 * methods are virtual and will be provided by a version specific concrete
 * metadata_checker.
 */
class metadata_checker {
public:
	metadata_checker(size_t max_metadata_size, metadata_fetcher *metadata_fetcher);

	virtual ~metadata_checker();

	virtual void get_active_indices(uint32_t *active_index,
					uint32_t *previous_active_index) = 0;

	virtual void check_regular(unsigned int boot_index) = 0;
	virtual void check_ready_for_staging(unsigned int boot_index) = 0;
	virtual void check_ready_to_activate(unsigned int boot_index) = 0;
	virtual void check_trial(unsigned int boot_index) = 0;
	virtual void check_fallback_to_previous(unsigned int boot_index) = 0;

protected:
	void load_metadata(void);

	metadata_fetcher *m_metadata_fetcher;
	uint8_t *m_meta_buf;
	size_t m_meta_buf_size;

private:
	metadata_checker(const metadata_checker &);
	const metadata_checker &operator=(const metadata_checker &);
};

#endif /* METADATA_CHECKER_H */
