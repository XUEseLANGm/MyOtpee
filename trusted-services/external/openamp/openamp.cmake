#-------------------------------------------------------------------------------
# Copyright (c) 2022 Linaro Limited
# Copyright (c) 2022-2023, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

set (OPENAMP_URL "https://github.com/OpenAMP/open-amp.git"
		CACHE STRING "OpenAMP repository URL")
set (OPENAMP_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/openamp_install"
		CACHE PATH "OpenAMP installation directory")
set (OPENAMP_SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/openamp"
		CACHE PATH "OpenAMP source code directory")
set (OPENAMP_PACKAGE_DIR "${OPENAMP_INSTALL_DIR}/openamp/cmake"
		CACHE PATH "OpenAMP CMake package directory")
set (OPENAMP_REFSPEC "347397decaa43372fc4d00f965640ebde042966d"
		CACHE STRING "The version of openamp to use")

set(GIT_OPTIONS_OPENAMP
    GIT_REPOSITORY ${OPENAMP_URL}
    GIT_TAG ${OPENAMP_REFSPEC}
    GIT_SHALLOW FALSE
)

if(NOT OPENAMP_DEBUG)
	set(OPENAMP_BUILD_TYPE "Release")
else()
	set(OPENAMP_BUILD_TYPE "Debug")
endif()

# Add libmetal dependency
include(${TS_ROOT}/external/openamp/libmetal.cmake)

include(FetchContent)

# Checking git
find_program(GIT_COMMAND "git")
if (NOT GIT_COMMAND)
	message(FATAL_ERROR "Please install git")
endif()

# Only pass libc settings to openamp if needed. For environments where the
# standard library is not overridden, this is not needed.
if(TARGET stdlib::c)
	include(${TS_ROOT}/tools/cmake/common/PropertyCopy.cmake)

	# Save libc settings
	save_interface_target_properties(TGT stdlib::c PREFIX LIBC)
	# Translate libc settings to cmake code fragment. Will be inserted into
	# libmetal-init-cache.cmake.in when LazyFetch configures the file.
	translate_interface_target_properties(PREFIX LIBC RES _cmake_fragment)
	unset_saved_properties(LIBC)
endif()

include(${TS_ROOT}/tools/cmake/common/LazyFetch.cmake REQUIRED)
LazyFetch_MakeAvailable(DEP_NAME openamp
    FETCH_OPTIONS "${GIT_OPTIONS_OPENAMP}"
    INSTALL_DIR "${OPENAMP_INSTALL_DIR}"
    CACHE_FILE "${TS_ROOT}/external/openamp/openamp-init-cache.cmake.in"
    SOURCE_DIR "${OPENAMP_SOURCE_DIR}"
)
unset(_cmake_fragment)

#Create an imported target to have clean abstraction in the build-system.
add_library(openamp STATIC IMPORTED)
set_property(TARGET openamp PROPERTY IMPORTED_LOCATION "${OPENAMP_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}open_amp${CMAKE_STATIC_LIBRARY_SUFFIX}")
set_property(TARGET openamp PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${OPENAMP_INSTALL_DIR}/include")
target_link_libraries(openamp INTERFACE libmetal)
