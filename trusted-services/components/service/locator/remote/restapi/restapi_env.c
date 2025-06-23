/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "restapi_location_strategy.h"
#include "service_locator.h"

void service_locator_envinit(void)
{
	/**
	 * Register service location strategy for reaching services using
	 * the FW Test API or any other REST API that presents a remotely
	 * reachable test interface to a DUT. Call requests are made using
	 * an HTTP based RPC layer.
	 */
	service_locator_register_strategy(restapi_location_strategy());
}
