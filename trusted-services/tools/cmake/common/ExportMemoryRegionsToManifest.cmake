#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#[===[.rst:
.. cmake:command:: export_memory_regions_to_manifest

	Exports the memory regions from an ELF format SP into a manifest file fragment.

	.. code:: cmake

		export_memory_regions_to_manifest(TARGET NAME RES)

	INPUTS:

	``TARGET``
	Build target

	``NAME``
	The UUID of the SP as a string.

	``RES``
	The name of the SP.

#]===]
function(export_memory_regions_to_manifest)
	set(options)
	set(oneValueArgs TARGET NAME RES)
	set(multiValueArgs)
	cmake_parse_arguments(MY "${options}" "${oneValueArgs}"
						"${multiValueArgs}" ${ARGN} )

	find_package(Python3 REQUIRED COMPONENTS Interpreter)

	add_custom_command(
		TARGET ${MY_TARGET} POST_BUILD
		COMMAND ${Python3_EXECUTABLE} ${TS_ROOT}/tools/python/elf_segments_to_manifest.py
				$<TARGET_FILE:${MY_TARGET}>
				$<TARGET_FILE_DIR:${MY_TARGET}>/${MY_NAME})
	if (MY_RES)
		set(${MY_RES} $<TARGET_FILE_DIR:${MY_TARGET}>/${MY_NAME} PARENT_SCOPE)
	endif()
endfunction()
