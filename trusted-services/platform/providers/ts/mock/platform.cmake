#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Platform definition for the 'mock' platform.  This platform provides
# mock implementations for all platform driver dependences.  This should
# never be used for a production build but is useful build testing and for
# running tests that don't rely on hardware backed peripherals.
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

get_property(_platform_driver_dependencies TARGET ${TGT}
	PROPERTY TS_PLATFORM_DRIVER_DEPENDENCIES
)

# Map platform dependencies to suitable drivers for this platform
if ("trng" IN_LIST _platform_driver_dependencies)
	target_sources(${TGT} PRIVATE "${TS_ROOT}/platform/drivers/mock/mock_trng.c")
endif()
