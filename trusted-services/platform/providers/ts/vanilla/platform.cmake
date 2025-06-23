#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Platform definition for the 'vanilla' platform.  The vanilla platform
# doesn't provide any hardware backed services so it should only be used
# when an environment provides all necessary native services for a
# deployment.
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

get_property(_platform_driver_dependencies TARGET ${TGT}
	PROPERTY TS_PLATFORM_DRIVER_DEPENDENCIES
)

# Flag error if there are platform driver dependencies.  This will happen if
# a suitable platform has not been specified.
if (_platform_driver_dependencies)
	message(FATAL_ERROR "Need to specify a compatible platform.  Deployment depends on platform drivers: ${_platform_driver_dependencies}")
endif()
