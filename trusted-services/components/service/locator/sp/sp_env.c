/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service_locator.h>
#include <service/locator/sp/ffa/spffa_location_strategy.h>


void service_locator_envinit(void)
{
	/*
	 * Register all service location strategies that could be used
	 * to locate services from a secure partition.
	 */
	service_locator_register_strategy(sp_ts_location_strategy());
}
