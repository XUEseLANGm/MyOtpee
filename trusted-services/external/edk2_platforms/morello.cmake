#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if (DEFINED ENV{TS_EDK2_PLATFORMS_PATH})
	# Use externally provided source tree
	set(EDK2_PLATFORMS_PATH $ENV{TS_EDK2_PLATFORMS_PATH} CACHE PATH "edk2-platforms location" FORCE)
else()
	# Otherwise clone the morello edk2-platforms repo
	set(EDK2_PLATFORMS_URL "https://git.morello-project.org/morello/edk2-platforms.git" CACHE STRING "edk2-platforms repository URL")
	set(EDK2_PLATFORMS_REFSPEC "morello/master" CACHE STRING "edk2-platforms git refspec")
	set(EDK2_PLATFORMS_PATH "${CMAKE_CURRENT_BINARY_DIR}/_deps/edk2-platforms-src" CACHE PATH "Location of edk2-platforms source")

	set(GIT_OPTIONS
		GIT_REPOSITORY ${EDK2_PLATFORMS_URL}
		GIT_TAG ${EDK2_PLATFORMS_REFSPEC}
	)

	include(${TS_ROOT}/tools/cmake/common/LazyFetch.cmake REQUIRED)
	LazyFetch_MakeAvailable(
		DEP_NAME edk2-platforms
		FETCH_OPTIONS "${GIT_OPTIONS}"
		SOURCE_DIR ${EDK2_PLATFORMS_PATH}
	)
endif()
