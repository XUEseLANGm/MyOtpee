#-------------------------------------------------------------------------------
# Copyright (c) 2020-2024, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#[===[.rst:
NanoPB integration for cmake
----------------------------

This module will:
	- use LazyFetch to download nanopb and build the static library and the generator.
	  Usual LazyFetch configuration to use prefetched source or prebuilt binaries apply.
	- run find_module() to import the static library
	- run find_executable() import the generator to the build (extend PYTHONPATH) and
	  define a cmake function to provide access to the generator to build nanopb files.

Note: see requirements.txt for dependencies which need to be installed in the build
environment to use this module.

#]===]

#### Get the dependency

set(NANOPB_URL "https://github.com/nanopb/nanopb.git"
		CACHE STRING "nanopb repository URL")
set(NANOPB_REFSPEC "nanopb-0.4.8"
		CACHE STRING "nanopb git refspec")
set(NANOPB_SOURCE_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/nanopb-src"
		CACHE PATH "nanopb source-code")
set(NANOPB_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/nanopb_install"
		CACHE PATH "nanopb installation directory")
set(NANOPB_BUILD_TYPE "Release"
		CACHE STRING "nanopb build type")

# Checking git
find_program(GIT_COMMAND "git")
if (NOT GIT_COMMAND)
	message(FATAL_ERROR "Please install git")
endif()

set(GIT_OPTIONS
	GIT_REPOSITORY ${NANOPB_URL}
	GIT_TAG ${NANOPB_REFSPEC}
	GIT_SHALLOW FALSE
	#See the .patch file for details on why it is needed.
	PATCH_COMMAND git stash
		COMMAND git apply ${CMAKE_CURRENT_LIST_DIR}/0001-Fix-race-condition-in-directory-creation.patch
  )

# Only pass libc settings to nanopb if needed. For environments where the standard
# library is not overridden, this is not needed.
if(TARGET stdlib::c)
	include(${TS_ROOT}/tools/cmake/common/PropertyCopy.cmake)

	# Save libc settings
	save_interface_target_properties(TGT stdlib::c PREFIX LIBC)
	# Translate libc settings to cmake code fragment. Will be inserted into
	# nanopb-init-cache.cmake.in when LazyFetch configures the file.
	translate_interface_target_properties(PREFIX LIBC RES _cmake_fragment)
	unset_saved_properties(LIBC)
endif()

# Nanopb build depends on python. Discover python here and pass the result to
# nanopb build through the initial cache file.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Use LazyFetch to manage the external dependency.
include(${TS_ROOT}/tools/cmake/common/LazyFetch.cmake REQUIRED)
LazyFetch_MakeAvailable(DEP_NAME nanopb
	FETCH_OPTIONS ${GIT_OPTIONS}
	INSTALL_DIR ${NANOPB_INSTALL_DIR}
	PACKAGE_DIR ${NANOPB_INSTALL_DIR}
	CACHE_FILE "${TS_ROOT}/external/nanopb/nanopb-init-cache.cmake.in"
	SOURCE_DIR "${NANOPB_SOURCE_DIR}"
  )
unset(_cmake_fragment)

if(TARGET stdlib::c)
	target_link_libraries(nanopb::protobuf-nanopb-static INTERFACE stdlib::c)
endif()

#### Build access to the protobuf compiler
find_program(NANOPB_GENERATOR_PATH
			NAMES nanopb_generator.py
			HINTS ${NANOPB_INSTALL_DIR}/bin ${NANOPB_INSTALL_DIR}/sbin
			DOC "nanopb protobuf compiler"
			NO_DEFAULT_PATH
		)

if (NOT NANOPB_GENERATOR_PATH)
	message(FATAL_ERROR "Nanopb generator was not found!")
endif()

#[===[.rst:
.. cmake:command:: protobuf_generate

  .. code-block:: cmake

	 protobuf_generate(SRC file.proto
					 TGT foo
					 NAMESPACE bar
					 BASE_DIR "proto/definitions")

  Run the ``nanopb_generator`` to compile a protobuf definition file into C source.
  Generated source file will be added to the source list of ``TGT``. Protobuf
  compilation will take part before TGT+NAMESPACE is built.

  Protobuf file names added to the same TGT must not collide.

  Inputs:

  ``SRC``
	Path to of the protobuf file to process. Either absolute or relative to the
	callers location.

  ``TGT``
	Name of target to compile generated source files.

  ``NAMESPACE``
	Namespace to put generated files under. Specifies include path and allows
	separating colliding protobuf files.

  ``BASE_DIR``
	Base directory. Generated files are located relative to this base.

#]===]
function(protobuf_generate)
	set(_options )
	set(_oneValueArgs SRC TGT NAMESPACE BASE_DIR)
	set(_multiValueArgs )

	cmake_parse_arguments(PARAMS "${_options}" "${_oneValueArgs}" "${_multiValueArgs}" ${ARGN})

	#Verify mandatory parameters
	if (NOT DEFINED PARAMS_SRC)
		message(FATAL_ERROR "nanopb_generate(): mandatory parameter SRC missing.")
	endif()
	if (NOT DEFINED PARAMS_TGT)
		message(FATAL_ERROR "nanopb_generate(): mandatory parameter TGT missing.")
	endif()
	if (NOT DEFINED PARAMS_NAMESPACE)
		message(FATAL_ERROR "nanopb_generate(): mandatory parameter NAMESPACE missing.")
	endif()
	if (NOT DEFINED PARAMS_BASE_DIR)
		message(FATAL_ERROR "nanopb_generate(): mandatory parameter BASE_DIR missing.")
	endif()

	#If SRC is not absolute make it relative to the callers location.
	if (NOT IS_ABSOLUTE ${PARAMS_SRC})
		set(PARAMS_SRC "${CMAKE_CURRENT_LIST_DIR}/${PARAMS_SRC}")
	endif()

	#Calculate the output directory
	set(_OUT_DIR_BASE ${CMAKE_BINARY_DIR}/src/${PARAMS_NAMESPACE})
	#Calculate output file names
	get_filename_component(_BASENAME ${PARAMS_SRC} NAME_WE)

	#Get relative path or SRC to BASE_DIR
	file(RELATIVE_PATH _SRC_REL ${PARAMS_BASE_DIR} ${PARAMS_SRC})
	get_filename_component(_OUT_DIR_REL ${_SRC_REL} DIRECTORY )

	#Calculate output file paths
	set(_OUT_C "${_OUT_DIR_BASE}/${_OUT_DIR_REL}/${_BASENAME}.pb.c")
	set(_OUT_H "${_OUT_DIR_BASE}/${_OUT_DIR_REL}/${_BASENAME}.pb.h")

	#some helper variables for the purpose of readability
	set(_nanopb_target "nanopb_generate_${PARAMS_TGT}_${PARAMS_NAMESPACE}")
	set(_nanopb_fake_file "nanopb_generate_ff_${PARAMS_TGT}")

	if (NOT TARGET "${_nanopb_target}")
		#Tell cmake the dependency (source) file is fake.
		set_source_files_properties("${_nanopb_fake_file}" PROPERTIES SYMBOLIC "true")
		#Create a custom target which depends on a "fake" file.
		add_custom_target("${_nanopb_target}"
							DEPENDS "${_nanopb_fake_file}")
		#Add a custom command to the target to create output directory.
		add_custom_command(OUTPUT "${_nanopb_fake_file}"
			COMMAND ${CMAKE_COMMAND} -E make_directory ${_OUT_DIR_BASE}/${_OUT_DIR_REL}
			COMMENT "Generating source from protobuf definitions for target ${PARAMS_TGT}")
		#Ensure protobuf build happens before test target.
		add_dependencies(${PARAMS_TGT} ${_nanopb_target})
		#Add include path to protobuf output.
		target_include_directories(${PARAMS_TGT} PRIVATE ${_OUT_DIR_BASE})
	endif()

	#Append a protobuf generator command to the nanopb_generate target.
	add_custom_command(OUTPUT "${_OUT_C}" "${_OUT_H}"
					   COMMAND
					   ${CMAKE_COMMAND} -E env PYTHONPATH=${NANOPB_INSTALL_DIR}/lib/python
					   ${Python3_EXECUTABLE} ${NANOPB_GENERATOR_PATH}
						  -I ${PARAMS_BASE_DIR}
						  -D ${_OUT_DIR_BASE}
						  ${_SRC_REL}
					   DEPENDS "${PARAMS_SRC}")

	#Add generated file to the target
	set_property(SOURCE "${_OUT_C}" PROPERTY GENERATED TRUE)
	target_sources(${PARAMS_TGT} PRIVATE "${_OUT_C}")
endfunction()

#[===[.rst:
.. cmake:command:: protobuf_generate_all

  .. code-block:: cmake

	 protobuf_generate_all(TGT foo
					 NAMESPACE bar
					 BASE_DIR "proto/definitions")

  Generates C code from all .proto files listed in the target
  property PROTOBUF_FILES.

  Inputs:

   ``TGT``
	Name of target to compile generated source files.

  ``NAMESPACE``
	Namespace to put generated files under. Specifies include path and allows
	separating colliding protobuf files.

  ``BASE_DIR``
	Base directory. Generated files are located relative to this base.

#]===]
function(protobuf_generate_all)
	set(_options )
	set(_oneValueArgs TGT NAMESPACE BASE_DIR)
	set(_multiValueArgs )

	cmake_parse_arguments(PARAMS "${_options}" "${_oneValueArgs}" "${_multiValueArgs}" ${ARGN})

	#Verify mandatory parameters
	if (NOT DEFINED PARAMS_TGT)
		message(FATAL_ERROR "nanopb_generate_all(): mandatory parameter TGT missing.")
	endif()
	if (NOT DEFINED PARAMS_NAMESPACE)
		message(FATAL_ERROR "nanopb_generate_all(): mandatory parameter NAMESPACE missing.")
	endif()
	if (NOT DEFINED PARAMS_BASE_DIR)
		message(FATAL_ERROR "nanopb_generate_all(): mandatory parameter BASE_DIR missing.")
	endif()

	get_property(_protolist TARGET ${PARAMS_TGT} PROPERTY PROTOBUF_FILES)

	#Build of each .proto file
	foreach(_file IN LISTS _protolist)
		protobuf_generate(
				TGT ${PARAMS_TGT}
				SRC "${_file}"
				NAMESPACE ${PARAMS_NAMESPACE}
				BASE_DIR ${PARAMS_BASE_DIR})
	endforeach()
endfunction()
