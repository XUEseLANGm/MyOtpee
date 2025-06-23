/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "service/fwu/test/fwu_dut_factory/fwu_dut_factory.h"

#include "service/fwu/test/fwu_dut/proxy/proxy_fwu_dut.h"

/*
 * A factory for constructing fwu_dut objects for remote access to
 * a real fwu_service provider. Because the service provider will have
 * been configured using its own mechanism, configuration parameters
 * passed on 'create' are ignored.
 */
fwu_dut *fwu_dut_factory::create(unsigned int num_locations, bool allow_partial_updates)
{
	/* Determined by FWU service provider configuration */
	(void)num_locations;
	(void)allow_partial_updates;

	/* Construct a proxy_fwu_dut with no explicit link to a backend fwu_dut */
	return new proxy_fwu_dut(num_locations, FWU_METADATA_VERSION, NULL);
}