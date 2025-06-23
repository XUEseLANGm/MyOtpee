#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022 Linaro Limited
# Copyright (c) 2021-2023, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

set (LIBMETAL_URL "https://github.com/OpenAMP/libmetal.git"
		CACHE STRING "libmetal repository URL")
set (LIBMETAL_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/libmetal_install"
		CACHE PATH "libmetal installation directory")
set(LIBMETAL_SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/libmetal"
		CACHE PATH "libmetal source-code")
set (LIBMETAL_PACKAGE_DIR "${LIBMETAL_INSTALL_DIR}/libmetal/cmake"
		CACHE PATH "libmetal CMake package directory")
set (LIBMETAL_REFSPEC "f252f0e007fbfb8b3a52b1d5901250ddac96baad"
		CACHE STRING "The version of libmetal to use")
set(LIBMETAL_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/libmetal-build")

set(GIT_OPTIONS
    GIT_REPOSITORY ${LIBMETAL_URL}
    GIT_TAG ${LIBMETAL_REFSPEC}
    GIT_SHALLOW FALSE
)

if(NOT LIBMETAL_DEBUG)
	set(LIBMETAL_BUILD_TYPE "Release")
else()
	set(LIBMETAL_BUILD_TYPE "Debug")
endif()

include(FetchContent)

# Checking git
find_program(GIT_COMMAND "git")
if (NOT GIT_COMMAND)
	message(FATAL_ERROR "Please install git")
endif()

# Only pass libc settings to libmetal if needed. For environments where the
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
LazyFetch_MakeAvailable(DEP_NAME libmetal
    FETCH_OPTIONS "${GIT_OPTIONS}"
    INSTALL_DIR "${LIBMETAL_INSTALL_DIR}"
    CACHE_FILE "${TS_ROOT}/external/openamp/libmetal-init-cache.cmake.in"
    SOURCE_DIR "${LIBMETAL_SOURCE_DIR}"
)
unset(_cmake_fragment)

#Create an imported target to have clean abstraction in the build-system.
add_library(libmetal STATIC IMPORTED)
set_property(TARGET libmetal PROPERTY IMPORTED_LOCATION "${LIBMETAL_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}metal${CMAKE_STATIC_LIBRARY_SUFFIX}")
set_property(TARGET libmetal PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${LIBMETAL_INSTALL_DIR}/include")
if(TARGET stdlib::c)
	target_link_libraries(libmetal INTERFACE stdlib::c)
endif()
