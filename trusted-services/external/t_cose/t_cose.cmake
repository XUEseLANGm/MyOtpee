#-------------------------------------------------------------------------------
# Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# t_cose is a library for signing CBOR tokens using COSE_Sign1
#-------------------------------------------------------------------------------

set(T_COSE_URL "https://github.com/laurencelundblade/t_cose.git" CACHE STRING "t_cose repository URL")
set(T_COSE_REFSPEC "fc3a4b2c7196ff582e8242de8bd4a1bc4eec577f" CACHE STRING "t_cose git refspec")
set(T_COSE_SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/t_cose-src" CACHE PATH "t_cose installation directory")
set(T_COSE_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/t_cose_install" CACHE PATH "t_cose installation directory")
set(T_COSE_BUILD_TYPE "Release" CACHE STRING "t_cose build type")

set(GIT_OPTIONS
	GIT_REPOSITORY ${T_COSE_URL}
	GIT_TAG ${T_COSE_REFSPEC}
	GIT_SHALLOW FALSE

	PATCH_COMMAND git stash
		COMMAND git branch -f bf-patch
		COMMAND git am ${CMAKE_CURRENT_LIST_DIR}/0001-add-install-definition.patch
						${CMAKE_CURRENT_LIST_DIR}/0002-Fix-stop-overriding-C_FLAGS-from-environment.patch
		COMMAND git reset bf-patch
)

include(${TS_ROOT}/tools/cmake/common/PropertyCopy.cmake)

# Only pass libc settings to t-cose if needed. For environments where the standard
# library is not overridden, this is not needed.
if(TARGET stdlib::c)
	# Save libc settings
	save_interface_target_properties(TGT stdlib::c PREFIX LIBC)
	# Translate libc settings to cmake code fragment. Will be inserted into
	# t_cose-init-cache.cmake.in when LazyFetch configures the file.
	translate_interface_target_properties(PREFIX LIBC RES _cmake_fragment)
	unset_saved_properties(LIBC)
endif()

# Prepare include paths for dependencies that t_codse has on external components
save_interface_target_properties(TGT qcbor PREFIX QCBOR)
translate_interface_target_properties(PREFIX QCBOR RES _cmake_fragment1)
unset_saved_properties(QCBOR)
string(APPEND _cmake_fragment "\n${_cmake_fragment1}")
unset(_cmake_fragment1)

if (NOT DEFINED PSA_CRYPTO_API_INCLUDE)
	string(CONCAT _msg "Mandatory parameter PSA_CRYPTO_API_INCLUDE is not defined. Please include a component which"
					   " sets this variable or pass -DPSA_CRYPTO_API_INCLUDE=<path> where <path> is the location of"
					   " PSA API headers.")
	message(FATAL_ERROR ${_msg} )
endif()

translate_value_as_property(VALUE "${PSA_CRYPTO_API_INCLUDE}"
							PROPERTY INTERFACE_INCLUDE_DIRECTORIES
							RES _cmake_fragment1)
string(APPEND _cmake_fragment "\n${_cmake_fragment1}")
unset(_cmake_fragment1)

include(${TS_ROOT}/tools/cmake/common/LazyFetch.cmake REQUIRED)
LazyFetch_MakeAvailable(DEP_NAME t_cose
	FETCH_OPTIONS "${GIT_OPTIONS}"
	INSTALL_DIR ${T_COSE_INSTALL_DIR}
	CACHE_FILE "${CMAKE_CURRENT_LIST_DIR}/t_cose-init-cache.cmake.in"
	SOURCE_DIR "${T_COSE_SOURCE_DIR}"
	)
unset(_cmake_fragment)

# Create an imported target to have clean abstraction in the build-system.
add_library(t_cose STATIC IMPORTED)
target_link_libraries(t_cose INTERFACE qcbor)
set_property(TARGET t_cose PROPERTY IMPORTED_LOCATION "${T_COSE_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}t_cose${CMAKE_STATIC_LIBRARY_SUFFIX}")
set_property(TARGET t_cose PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${T_COSE_INSTALL_DIR}/include")
if(TARGET stdlib::c)
	target_link_libraries(t_cose INTERFACE stdlib::c)
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${T_COSE_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}t_cose${CMAKE_STATIC_LIBRARY_SUFFIX}")
