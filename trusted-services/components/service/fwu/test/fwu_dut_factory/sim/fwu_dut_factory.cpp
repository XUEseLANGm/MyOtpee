/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "service/fwu/test/fwu_dut_factory/fwu_dut_factory.h"

#include "service/fwu/test/fwu_dut/sim/sim_fwu_dut.h"

/*
 * A factory for constructing sim_fwu_dut objects. A sim_fwu_dut is an
 * aggregate of all storage and fwu related objects and is suitable for
 * component level testing. The sim_fwu_dut simulates the role of the
 * bootloader and device shutdown and boot-up.
 */
fwu_dut *fwu_dut_factory::create(unsigned int num_locations, bool allow_partial_updates)
{
	return new sim_fwu_dut(num_locations, FWU_METADATA_VERSION, allow_partial_updates);
}