#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/Uuid.cmake)

#[===[.rst:
.. cmake:command:: set_target_uuids

.. code:: cmake

set_target_uuids(
	SP_UUID <uuid>
	SP_NAME <name>
	)

INPUTS:

``SP_UUID``
The UUID of the SP as a string.

``SP_NAME``
The name of the SP.

#]===]

function (set_target_uuids)
	set(options)
	set(oneValueArgs TGT SP_UUID)
	set(multiValueArgs)
	cmake_parse_arguments(_MY_PARAMS "${options}" "${oneValueArgs}"
		"${multiValueArgs}" ${ARGN} )

	check_args(SP_UUID TGT)

	# Convert the UUID to a C char array initializer e.g.
	#  { 0x01, 0x10, 0x9c, 0xf8, 0xe5, 0xca, 0x44, 0x6f,
	#   0x9b, 0x55, 0xf3, 0xcd, 0xc6, 0x51, 0x10, 0xc8, }
	# and "pass it" to C files.
	uuid_canon_to_octets(UUID ${_MY_PARAMS_SP_UUID} RES UUID_OCTETS)
	list(JOIN UUID_OCTETS ", 0x" UUID_BYTES )
	set(UUID_BYTES "{ 0x${UUID_BYTES} }")
	target_compile_definitions(${_MY_PARAMS_TGT}
		PRIVATE OPTEE_SP_UUID_BYTES=${UUID_BYTES}
	)

	# Create a UUID structure with the UUID fileds
	# { 0x01109cf8, 0xe5ca, 0x446f, \
	# { 0x9b, 0x55, 0xf3, 0xcd, 0xc6, 0x51, 0x10, 0xc8 } }
	# and "pass it" to C files
	uuid_canon_to_fields(UUID ${_MY_PARAMS_SP_UUID}
			TIME_LOW "_uuid_timeLow"
			TIME_MID "_uuid_timeMid"
			TIME_HI_AND_VER "_uuid_timeHiAndVersion"
			CLOCK_AND_SEQ "_uuid_clockSeqAndNode")
	string(REGEX MATCHALL ".." _uuid_clockSeqAndNode "${_uuid_clockSeqAndNode}")
	list(JOIN _uuid_clockSeqAndNode ", 0x" _uuid_clockSeqAndNode)
	set(UUID_STRUCT "{ 0x${_uuid_timeLow}, 0x${_uuid_timeMid}, 0x${_uuid_timeHiAndVersion}, { 0x${_uuid_clockSeqAndNode} }}")
	target_compile_definitions(${_MY_PARAMS_TGT}
		PRIVATE OPTEE_SP_UUID=${UUID_STRUCT}
	)
endfunction()
