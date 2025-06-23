/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service_locator.h>
#include <service/locator/linux/ffa/linuxffa_location_strategy.h>
#include <service/locator/linux/mm_communicate/mm_communicate_location_strategy.h>

void service_locator_envinit(void)
{
	/*
	 * Register all service location strategies that could be used
	 * to locate services from Linux userspace.
	 */
	service_locator_register_strategy(linux_ts_location_strategy());
	service_locator_register_strategy(mm_communicate_location_strategy());
}
