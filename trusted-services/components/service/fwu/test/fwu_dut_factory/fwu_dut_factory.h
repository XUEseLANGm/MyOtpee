/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FWU_DUT_FACTORY_H
#define FWU_DUT_FACTORY_H

#include "service/fwu/test/fwu_dut/fwu_dut.h"

/*
 * A factory for constructing fwu_dut objects. To allow for different test
 * configurations, alternative implementations of the factory method are
 * possible. The fwu_dut_factory provides a common interface to allow test
 * cases that depend on a fwu_dut to be reused in different deployments.
 */
class fwu_dut_factory {
public:
	/**
	 * \brief Factory method to construct concrete fwu_dut objects
	 *
	 * \param[in]  num_locations  The number of updatable fw locations
	 * \param[in]  allow_partial_updates True if updating a subset of locations is permitted
	 *
	 * \return The constructed fwu_dut
	 */
	static fwu_dut *create(unsigned int num_locations, bool allow_partial_updates = false);

private:
	static const unsigned int FWU_METADATA_VERSION = 2;
};

#endif /* FWU_DUT_FACTORY_H */
