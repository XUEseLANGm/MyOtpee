# Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#[===[.rst:
Add build components to the current build.
------------------------------------------

#]===]


#[===[.rst:
.. cmake:command:: add_components

	.. code:: cmake

		add_components(TARGET <target name> COMPONENTS <list of component directories>)

	INPUTS:

	``BASE_DIR``
	If defined components are include relative to this directory. If nor paths must be
	relative to CMAKE_SOURCE_DIR or be absolute.

	``TARGET``
	The name of an already defined target to add components to.

	``COMPONENTS``
	List of components relative to :cmake:variable:`CMAKE_SOURCE_DIR`

#]===]

function(add_components)
	set(options  )
	set(oneValueArgs TARGET BASE_DIR)
	set(multiValueArgs COMPONENTS)
	cmake_parse_arguments(MY_PARAMS "${options}" "${oneValueArgs}"
						"${multiValueArgs}" ${ARGN} )

	if(NOT DEFINED MY_PARAMS_TARGET)
		message(FATAL_ERROR "add_component: mandatory parameter TARGET not defined!")
	endif()
	if(NOT DEFINED MY_PARAMS_COMPONENTS)
		message(FATAL_ERROR "add_component: mandatory parameter COMPONENTS not defined!")
	endif()
	if(DEFINED MY_PARAMS_BASE_DIR AND NOT MY_PARAMS_BASE_DIR MATCHES ".*/$")
		set(MY_PARAMS_BASE_DIR "${MY_PARAMS_BASE_DIR}/")
	endif()

	set(TGT ${MY_PARAMS_TARGET})
	foreach(_comp IN ITEMS ${MY_PARAMS_COMPONENTS})
		set(_file ${MY_PARAMS_BASE_DIR}${_comp}/component.cmake)
		include(${_file})
		set(CMAKE_CONFIGURE_DEPENDS ${_file})
	endforeach()
	# Remove duplicate settings
	foreach(_prop IN ITEMS INTERFACE_INCLUDE_DIRECTORIES INCLUDE_DIRECTORIES
						   INTERFACE_COMPILE_DEFINITIONS COMPILE_DEFINITIONS
						   INTERFACE_COMPILE_OPTIONS COMPILE_OPTIONS
						   INTERFACE_SOURCES SOURCES
						   PUBLIC_HEADER)
		get_property(_tmp TARGET ${MY_PARAMS_TARGET} PROPERTY ${_prop})
		list(REMOVE_DUPLICATES _tmp)
		set_property(TARGET ${MY_PARAMS_TARGET} PROPERTY ${_prop} ${_tmp})
	endforeach()
endfunction()
