/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "service/fwu/test/fwu_dut_factory/fwu_dut_factory.h"

#include "service/fwu/test/fwu_dut/proxy/proxy_fwu_dut.h"
#include "service/fwu/test/fwu_dut/sim/sim_fwu_dut.h"
#include "service/locator/standalone/services/fwu/fwu_service_context.h"

/*
 * A factory for constructing fwu_dut objects for remote access to
 * the fwu_service associated with a simulated device. The factory
 * method actually constructs two concrete fwu_dut objects, a
 * proxy_fwu_dut and a sim_fwu_dut. The proxy_fwu_dut is returned
 * to the caller and provides the client interface used by test
 * cases. The sim_fwu_dut forms the backend for the standalone
 * fwu service.
 */
fwu_dut *fwu_dut_factory::create(unsigned int num_locations, bool allow_partial_updates)
{
	/* Construct and set the simulated dut that provides the configured
	 * device and fwu service provider.
	 */
	sim_fwu_dut *sim_dut =
		new sim_fwu_dut(num_locations, FWU_METADATA_VERSION, allow_partial_updates);

	fwu_service_context_set_provider(sim_dut->get_service_interface());

	/* Construct a proxy_fwu_dut chained to the sim_fwu_dut. On deletion,
	 * the proxy_fwu_dut deletes the associated sim_fwu_dut.
	 */
	return new proxy_fwu_dut(num_locations, FWU_METADATA_VERSION, sim_dut);
}