#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

include_guard()

#[===[.rst:
RFC 4122 compatible UUID manipulation routines
---------------------------------------------

The functionality in this file allows manipulating (which mostly means conversion) of UUID strings
to various formats used in the TS build system.

#]===]

#[===[.rst:
.. cmake:command:: uuid_canon_to_octets

  .. code-block:: cmake

    uuid_canon_to_octets(UUID <canonical UUID string> RES <output variable name>)

	Convert a canonical UUID string to list of bytes, where each byte is represented as a two digit
	hex octet without any prefix of suffix. Order of bytes will match the order of octets in the
	canonical string left to right.

	INPUTS:

	``UUID``
	Canonical UUID string.

    OUTPUTS:

	``RES``
	Name of variable to store the result to. The result is a list of strings, where each list item
	is a two digit hex digit, without any prefix or suffix.

#]===]
function(uuid_canon_to_octets)
	set(options)
	set(oneValueArgs UUID RES)
	set(multiValueArgs)
	cmake_parse_arguments(_MY_PARAMS "${options}" "${oneValueArgs}"
		"${multiValueArgs}" ${ARGN} )

	check_args(UUID RES)

	string(REGEX MATCHALL "([A-Za-z0-9][A-Za-z0-9])" _hex_bytes "${_MY_PARAMS_UUID}")
	list(LENGTH _hex_bytes _len)
	if(NOT _len EQUAL 16)
		message(FATAL_ERROR "Failed to convert UUID \"${_MY_PARAMS_UUID}\" to bytes. Failed to get exactly 16 octets.")
	endif()
	set(${_MY_PARAMS_RES} ${_hex_bytes} PARENT_SCOPE)
endfunction()

#[===[.rst:
.. cmake:command:: uuid_canon_to_fields

  .. code-block:: cmake

    uuid_canon_to_fields(UUID <canonical UUIdD string> TIME_LOW <output variable name> TIME_MID <output variable name>
					TIME_HI_AND_VER <output variable name> CLOCK_AND_SEQ <output variable name>)

	Convert a canonical UUID string to UUID fields. Each field is a

	INPUTS:

	``UUID``
	Canonical UUID string.

    OUTPUTS:
    ``TIME_LOW``
    Name of variable to store the time low filed.

    ``TIME_MID``
    Name of variable to store the time mid filed.

    ``TIME_HI_AND_VER``
    Name of variable to store the time hi and version filed.

    ``CLOCK_AND_SEQ``
    Name of variable to store the clock and sequence filed.

#]===]
function(uuid_canon_to_fields)
	set(options)
	set(oneValueArgs UUID TIME_LOW TIME_MID TIME_HI_AND_VER CLOCK_AND_SEQ)
	set(multiValueArgs)
	cmake_parse_arguments(_MY_PARAMS "${options}" "${oneValueArgs}"
		"${multiValueArgs}" ${ARGN} )

	check_args(UUID TIME_LOW TIME_MID TIME_HI_AND_VER CLOCK_AND_SEQ)
	uuid_canon_to_octets(UUID ${_MY_PARAMS_UUID} RES _uuid_octets)

	#Split the list of bytes in to the struct fields
	list(SUBLIST _uuid_octets 0 4 _uuid_timeLow)
	list(JOIN _uuid_timeLow "" _uuid_timeLow)

	list(SUBLIST _uuid_octets 4 2 _uuid_timeMid)
	list(JOIN _uuid_timeMid "" _uuid_timeMid)

	list(SUBLIST _uuid_octets 6 2 _uuid_timeHiAndVersion)
	list(JOIN _uuid_timeHiAndVersion "" _uuid_timeHiAndVersion)

	list(SUBLIST _uuid_octets 8 8 _uuid_clockSeqAndNode)
	list(JOIN _uuid_clockSeqAndNode "" _uuid_clockSeqAndNode)

	set(${_MY_PARAMS_TIME_LOW} ${_uuid_timeLow} PARENT_SCOPE)
	set(${_MY_PARAMS_TIME_MID} ${_uuid_timeMid} PARENT_SCOPE)
	set(${_MY_PARAMS_TIME_HI_AND_VER} ${_uuid_timeHiAndVersion} PARENT_SCOPE)
	set(${_MY_PARAMS_CLOCK_AND_SEQ} ${_uuid_clockSeqAndNode} PARENT_SCOPE)
endfunction()

#[===[.rst:
.. cmake:command:: uuid_canon_to_le_words

  .. code-block:: cmake

    uuid_canon_to_le_words(UUID <canonical UUID string> RES <output variable name>)

	Convert a canonical UUID string to list of 32bit wide little-endian numbers represented
	as hex strings.

	INPUTS:

	``UUID``
	Canonical UUID string.

	``RES``
	Name of variable to store the result to.

#]===]
function(uuid_canon_to_le_words)
	set(options)
	set(oneValueArgs UUID RES)
	set(multiValueArgs)
	cmake_parse_arguments(_MY_PARAMS "${options}" "${oneValueArgs}"
		"${multiValueArgs}" ${ARGN} )

	check_args(UUID RES)
	uuid_canon_to_octets(UUID ${_MY_PARAMS_UUID} RES _uuid_octets)

    # Separate 32 bit chunks
	list(SUBLIST _uuid_octets 0 4 _word1)
	list(SUBLIST _uuid_octets 4 4 _word2)
	list(SUBLIST _uuid_octets 8 4 _word3)
	list(SUBLIST _uuid_octets 12 4 _word4)

    # Reverse octet order each word
	list(REVERSE _word1)
	list(REVERSE _word2)
	list(REVERSE _word3)
	list(REVERSE _word4)

    # Concatenate octets of each word to a single string
    list(JOIN _word1 "" _word1)
    list(JOIN _word2 "" _word2)
    list(JOIN _word3 "" _word3)
    list(JOIN _word4 "" _word4)

    # Return the result
	set(${_MY_PARAMS_RES} "${_word1}" "${_word2}" "${_word3}" "${_word4}" PARENT_SCOPE)
endfunction()
