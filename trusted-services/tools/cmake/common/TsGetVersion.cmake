#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

include_guard(DIRECTORY)

include(${TS_ROOT}/tools/cmake/common/Utils.cmake REQUIRED)

#[===[.rst:
.. cmake:command:: version_semver_read

	.. code:: cmake

		version_semver_read(FILE <path> MAJOR <major> MINOR <minor> PATCH <patch>)

	Parse version number from file to variables. The file must contain the version number in
	semantic versioning format (https://semver.org). The file must not contain anything else, e.g.
	no newline at the end, etc.

	INPUTS:

	``FILE``
	Path to file that contains the version number.

	OUTPUTS:

	``MAJOR``
	Major version parsed from the file.

	``MINOR``
	Minor version parsed from the file.

	``PATCH``
	Patch version parsed from the file.

#]===]
function(version_semver_read)
	set(options)
	set(oneValueArgs FILE MAJOR MINOR PATCH)
	set(multiValueArgs)
	cmake_parse_arguments(_MY_PARAMS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

	check_args(version_semver_read FILE MAJOR MINOR PATCH)

	file(READ "${_MY_PARAMS_FILE}" version_string)

	# Note: double backslash is parsed in a quoted argument as just a single backslash. So the regex
	# itself contains a single backslash, which escapes the period to a literal period.
	string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$" regexOut "${version_string}")

	if(NOT CMAKE_MATCH_COUNT EQUAL 3)
		message(FATAL_ERROR
			"${_MY_PARAMS_FILE} contains invalid semantic version: \"${version_string}\"")
	endif()

	# CMAKE_MATCH_0 is the entire match, 1, 2, etc. are the actual capture groups
	set(${_MY_PARAMS_MAJOR} ${CMAKE_MATCH_1} PARENT_SCOPE)
	set(${_MY_PARAMS_MINOR} ${CMAKE_MATCH_2} PARENT_SCOPE)
	set(${_MY_PARAMS_PATCH} ${CMAKE_MATCH_3} PARENT_SCOPE)
endfunction()
