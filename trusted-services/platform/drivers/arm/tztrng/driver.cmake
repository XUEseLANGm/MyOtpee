#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

# Driver source location and version
set(ARM_TZTRNG_URL "https://github.com/ARM-software/TZ-TRNG.git" CACHE STRING "Arm TZ-TRNG driver repository URL")
set(ARM_TZTRNG_REFSPEC "1.0.0" CACHE STRING "Arm TZ-TRNG driver git refspec")

# Fetch driver source code from remote repository
include(FetchContent)

FetchContent_Declare(
	arm-tztrng
	GIT_REPOSITORY ${ARM_TZTRNG_URL}
	GIT_TAG ${ARM_TZTRNG_REFSPEC}
	GIT_SHALLOW FALSE
)

# FetchContent_GetProperties exports arm-tztrng_SOURCE_DIR and arm-tztrng_BINARY_DIR variables
FetchContent_GetProperties(arm-tztrng)
if(NOT arm-tztrng_POPULATED)
	message(STATUS "Fetching arm-tztrng")
	FetchContent_Populate(arm-tztrng)
endif()

# The driver has no cmake build support so it is necessary to bridge cmake variables to
# driver build parameters.

# Determine ARCH parameter
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
	set(_arm-tztrng_ARCH "arm64")
	set(_arm-tztrng_builddir "build-aarch64-linux-gnu")
else()
	message(FATAL_ERROR "Only arm builds of TZ-TRNG supported.")
endif()

# Determine the full path for the generated library and public header
set(_arm-tztrng_genlib "${arm-tztrng_SOURCE_DIR}/host/src/tztrng_lib/${_arm-tztrng_builddir}/libcc_tztrng.a")
set(_arm-tztrng_host_incpath "${arm-tztrng_SOURCE_DIR}/host/src/tztrng_lib/include")
set(_arm-tztrng_shared_incpath "${arm-tztrng_SOURCE_DIR}/shared/hw/include")

# Set HOST_PROJ_ROOT parameter to use TS provided build defines
set(_arm-tztrng_HOST_PROJ_ROOT ${CMAKE_CURRENT_LIST_DIR})

# Add custom command to build the driver library using the TZ-TRNG provided makefile
add_custom_command(
	OUTPUT ${_arm-tztrng_genlib}
	COMMAND make ARGS "ARCH=${_arm-tztrng_ARCH}"
	WORKING_DIRECTORY "${arm-tztrng_SOURCE_DIR}/host/src/tztrng_lib/"
)

# Define target for the library
add_custom_target(
	libcc_tztrng
	DEPENDS ${_arm-tztrng_genlib}
)

# Add generated library to build target
target_include_directories(${TGT} PRIVATE "${_arm-tztrng_host_incpath}")
target_include_directories(${TGT} PRIVATE "${_arm-tztrng_shared_incpath}")
target_link_libraries(${TGT} PRIVATE ${_arm-tztrng_genlib})
add_dependencies(${TGT} libcc_tztrng)

# Add adapter to map platform trng interface to tz-trng driver
target_sources(${TGT} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/tztrng_adapter.c")
