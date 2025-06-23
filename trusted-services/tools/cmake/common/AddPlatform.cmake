#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#[===[.rst:
Add platform provided components to a build
-------------------------------------------

#]===]


#[===[.rst:
.. cmake:command:: add_platform

	.. code:: cmake

		add_platform(TARGET <target name>)

	INPUTS:

	``TARGET``
	The name of an already defined target to add platform components to.

	``TS_PLATFORM``
	This global variable is used to construct a path to the platform specific cmake file.
	:variable:TS_PLATFORM can be set from the command line and the value must be lower case.

#]===]
function(add_platform)
	set(options  )
	set(oneValueArgs TARGET)
	cmake_parse_arguments(MY_PARAMS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN} )

	if(NOT DEFINED MY_PARAMS_TARGET)
		message(FATAL_ERROR "add_platform: mandatory parameter TARGET not defined!")
	endif()

	# Ensure file path conforms to lowercase project convention
	string(TOLOWER "${TS_PLATFORM}" _tmp)
	if (NOT "${TS_PLATFORM}" STREQUAL "${_tmp}")
			message(FATAL_ERROR "Value of TS_PLATFORM may only use lowercase letters. The current value"
								" \"${TS_PLATFORM}\" violates this.")
	endif()
	set(TGT ${MY_PARAMS_TARGET})
	include(${TS_PLATFORM_ROOT}/${TS_PLATFORM}/platform.cmake)
endfunction()
