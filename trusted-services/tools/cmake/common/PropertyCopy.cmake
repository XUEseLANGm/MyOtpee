#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#[===[.rst:
PropertyCopy.cmake
------------------

This module allows saving interface properties of a target to a set of variables and to translate
the variables to cmake script fragment of compiler and linker flag lists.
The main purpose is to allow transferring settings to sub-projects which need strong separation
(i.e. ExternalProject is used) or use a non CMake build system.

For CMake projects the data-flow is to save the settings to variables, translate these to cmake code
fragment, and then inject these to the sub-projects using a generated initial cache file.
Alternatively translate the saved values to list variables `<PREFIX>_CMAKE_C_FLAGS_INIT` and
`<PREFIX>_CMAKE_EXE_LINKER_FLAGS_INIT`, and pass these to the sub-project using the -D command-line
parameter.

For non CMake projects the data-flow is to save the properties to variables and the translate to
compiler and linker argument lists. Then use the generated `<PREFIX>_CMAKE_C_FLAGS_INIT` and
`<PREFIX>_CMAKE_EXE_LINKER_FLAGS_INIT` variables in a build system specific way (e.g. setting
`CFLAGS` and `LDFLAGS` environment variables) to configure the sub-project.

#]===]

#[===[.rst:
.. cmake:variable:: PROPERTYCOPY_DEFAULT_PROPERTY_LIST

Default list of properties to save and restore. It is used by functions in this file. Some of these
allow using a custom list instead by passing appropriate parameters.
#]===]
set(PROPERTYCOPY_DEFAULT_PROPERTY_LIST INTERFACE_COMPILE_DEFINITIONS
    INTERFACE_COMPILE_OPTIONS INTERFACE_INCLUDE_DIRECTORIES
    INTERFACE_LINK_DIRECTORIES INTERFACE_LINK_LIBRARIES INTERFACE_LINK_OPTIONS
    INTERFACE_POSITION_INDEPENDENT_CODE
    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES)

#[===[.rst:
.. cmake:command:: save_interface_target_properties

  .. code-block:: cmake

    save_interface_target_properties(TGT stdlib:c PREFIX LIBC)
    save_interface_target_properties(TGT stdlib:c PREFIX LIBC
                PROPERTIES INTERFACE_LINK_DIRECTORIES INTERFACE_LINK_LIBRARIES)

  Save interface properties of a target to a set of variables. Variables are named after the
  properties prefixed with the parameter <PREFIX>_. (i.e. FOO_INTERFACE_COMPILE_OPTIONS if the
  prefix was "FOO").
  The list of properties to be saved can be set using the PROPERTIES parameter. If this is not
  set, the :variable:`PROPERTYCOPY_DEFAULT_PROPERTY_LIST` is used.

  Inputs:
  ``TGT``
    Target to copy properties from.
  ``PROPERTIES``
    Optional. List of properties to save. If not set, the default list is used. See:
	:variable:`PROPERTYCOPY_DEFAULT_PROPERTY_LIST`.
  ``PREFIX``
    Prefix to use for output variable names.
  Outputs:
    A set of variables (see description).
#]===]
function(save_interface_target_properties)
    set(_OPTIONS_ARGS)
    set(_ONE_VALUE_ARGS TGT PREFIX)
    set(_MULTI_VALUE_ARGS PROPERTIES)
    cmake_parse_arguments(_MY_PARAMS "${_OPTIONS_ARGS}" "${_ONE_VALUE_ARGS}" "${_MULTI_VALUE_ARGS}" ${ARGN})

    if (NOT DEFINED _MY_PARAMS_PREFIX)
        message(FATAL_ERROR "Mandatory parameter PREFIX is not defined.")
    endif()
    if (NOT DEFINED _MY_PARAMS_TGT)
        message(FATAL_ERROR "Mandatory parameter TGT is not defined.")
    endif()
    if(NOT TARGET ${_MY_PARAMS_TGT})
        message(FATAL_ERROR "Target \"${_MY_PARAMS_TGT}\" does not exist.")
    endif()
    if (NOT DEFINED _MY_PARAMS_PROPERTIES)
        set(_MY_PARAMS_PROPERTIES ${PROPERTYCOPY_DEFAULT_PROPERTY_LIST})
    endif()

    foreach(_prop IN LISTS _MY_PARAMS_PROPERTIES )
        get_property(_set TARGET ${_MY_PARAMS_TGT} PROPERTY ${_prop} SET)
        if (_set)
            get_property(${_MY_PARAMS_PREFIX}_${_prop} TARGET ${_MY_PARAMS_TGT} PROPERTY ${_prop})
            set(${_MY_PARAMS_PREFIX}_${_prop} ${${_MY_PARAMS_PREFIX}_${_prop}} PARENT_SCOPE)
        endif()
    endforeach()
endfunction()

#[===[.rst:
.. cmake:command:: translate_interface_target_properties

  .. code-block:: cmake

    # To translate default set of properties saved to variables with ``LIBC_`` prefix
    # using :command:`save_interface_target_properties`. Result string returned to
    # ``_cmake_fragment``
    translate_interface_target_properties(PREFIX LIBC RES _cmake_fragment)

    # To translate default set of properties saved to variables with ``LIBC_`` prefix
    # using :command:`save_interface_target_properties`. Results saved to lists prefixed
    # with ``LIBC_``. List of generated lists is returned in ``_lists``
    translate_interface_target_properties(PREFIX LIBC RES _lists)

  Construct a string of cmake script fragment setting global cmake variables configuring
  build properties to match saved target interface settings. The script fragment is returned
  in ``RES``
  Intended usage is to help transferring target specific settings to sub projects using
  initial cache files.
  Warning: quotation in property values is not handled. This can cause problems e.g. with
           computed includes.

  If ``TO_LIST`` is passed translation will be done to a lists. ``RES`` will hold a list of
  list names where the settings are saved.
  This mode allows further processing on the lists, e.g. to be converted to ``CFLAGS`` or
  ``LDFLAGS`` environment variables.

  Works in tandem with :command:`save_interface_target_properties`.

  Inputs:
  ``PREFIX``
    Target to set properties on.
  ``VARS``
    Name of variables to copy from.
  ``TO_LIST``
    Translate to lists instead of cmake script fragment.
  Outputs
  ``RES``
    Name of variable to store the results to.
#]===]
function(translate_interface_target_properties)
    set(_OPTIONS_ARGS TO_LIST)
    set(_ONE_VALUE_ARGS PREFIX RES)
    set(_MULTI_VALUE_ARGS VARS)
    cmake_parse_arguments(_MY_PARAMS "${_OPTIONS_ARGS}" "${_ONE_VALUE_ARGS}" "${_MULTI_VALUE_ARGS}" ${ARGN})

    if (NOT DEFINED _MY_PARAMS_PREFIX)
        message(FATAL_ERROR "Mandatory parameter PREFIX is not defined.")
    endif()
    string(LENGTH "${_MY_PARAMS_PREFIX}_" _PREFIX_LENGT)

    if (NOT DEFINED _MY_PARAMS_RES)
        message(FATAL_ERROR "Mandatory parameter RES is not defined.")
    endif()

    if (DEFINED _MY_PARAMS_VARS)
        foreach(_VAR_NAME IN LISTS _MY_PARAMS_VARS)
            if (NOT DEFINED ${_VAR_NAME})
                message(FATAL_ERROR "Attempt to translate undefined variable \"${_VAR_NAME}\"")
            endif()

            string(SUBSTRING "${_VAR_NAME}" ${_PREFIX_LENGT} -1 _prop)
            _prc_translate(PROP "${_prop}" VALUE ${${_VAR_NAME}} RES _res)

            if(NOT "${_res}" STREQUAL "")
                list(GET _res 0 _global_var_name)
                list(GET _res 1 _global_var_value)
                list(APPEND ${_MY_PARAMS_PREFIX}_${_global_var_name} ${_global_var_value})
                if (NOT "${_MY_PARAMS_PREFIX}_${_global_var_name}" IN_LIST _RES)
                    list(APPEND _RES "${_MY_PARAMS_PREFIX}_${_global_var_name}")
                endif()
            endif()
        endforeach()
    else()
        foreach(_prop IN LISTS PROPERTYCOPY_DEFAULT_PROPERTY_LIST)
            set(_VAR_NAME "${_MY_PARAMS_PREFIX}_${_prop}")
            # Is the variable holding the value of the property available?
            if (DEFINED ${_VAR_NAME})
                _prc_translate(PROP "${_prop}" VALUE ${${_VAR_NAME}} RES _res)
                if(NOT "${_res}" STREQUAL "")
                    list(GET _res 0 _global_var_name)
                    list(GET _res 1 _global_var_value)
                    list(APPEND ${_MY_PARAMS_PREFIX}_${_global_var_name} ${_global_var_value})
                    if (NOT "${_MY_PARAMS_PREFIX}_${_global_var_name}" IN_LIST _RES)
                        list(APPEND _RES "${_MY_PARAMS_PREFIX}_${_global_var_name}")
                    endif()
                endif()
            endif()
        endforeach()
    endif()

    if (_MY_PARAMS_TO_LIST)
        foreach(_list_name IN LISTS _RES)
            set(${_list_name} ${${_list_name}} PARENT_SCOPE)
        endforeach()
        set(${_MY_PARAMS_RES} ${_RES} PARENT_SCOPE)
    else()
        foreach(_list_name IN LISTS _RES)
            string(SUBSTRING "${_list_name}" ${_PREFIX_LENGT} -1 _short_name)
            string(REPLACE ";" " " _list_value "${${_list_name}}")
            string(APPEND _STRING_RES "set(${_short_name} \"\${${_short_name}} ${_list_value}\" CACHE STRING \"\" FORCE)\n")
        endforeach()
        set(${_MY_PARAMS_RES} ${_STRING_RES} PARENT_SCOPE)
    endif()
endfunction()

#[===[.rst:
.. cmake:command:: translate_value_as_property

  .. code-block:: cmake

    translate_value_as_property(VALUE "/foo/bar/include;/foo/bar/include1"
                                PROPERTY INTERFACE_INCLUDE_DIRECTORIES
                                RES _cmake_fragment)

  Translate a value as the specified property would be. Can be used to translate variables not saved
  with :command:`save_interface_target_properties`

  Inputs:
  ``VALUE``
    Value to be converted.
  ``PROPERTY``
    The interface property to set conversion type.
  Outputs:
  ``RES``
    Name of variable to write result string to.
#]===]
function(translate_value_as_property)
    set(_OPTIONS_ARGS)
    set(_ONE_VALUE_ARGS VALUE PROPERTY RES)
    set(_MULTI_VALUE_ARGS)
    cmake_parse_arguments(_MY_PARAMS "${_OPTIONS_ARGS}" "${_ONE_VALUE_ARGS}" "${_MULTI_VALUE_ARGS}" ${ARGN})

    if (NOT DEFINED _MY_PARAMS_VALUE)
        message(FATAL_ERROR "Mandatory parameter VALUE is not defined.")
    endif()
    if (NOT DEFINED _MY_PARAMS_RES)
        message(FATAL_ERROR "Mandatory parameter RES is not defined.")
    endif()
    if (NOT DEFINED _MY_PARAMS_PROPERTY)
        message(FATAL_ERROR "Mandatory parameter PROPERTY is not defined.")
    endif()

    set(A_${_MY_PARAMS_PROPERTY} ${_MY_PARAMS_VALUE})
    translate_interface_target_properties(PREFIX A RES _cmake_fragment
            VARS A_${_MY_PARAMS_PROPERTY})
    set(${_MY_PARAMS_RES} ${_cmake_fragment} PARENT_SCOPE)
endfunction()

#[===[.rst:
.. cmake:command:: unset_saved_properties

  .. code-block:: cmake

    unset_saved_properties("LIBC")

  Unset saved properties. For cleaning up the variable name space.

  Inputs:
  ``PREFIX``
    Prefix to use for output variable names.
#]===]
macro(unset_saved_properties PREFIX)
    foreach(_prc_prop IN LISTS PROPERTYCOPY_DEFAULT_PROPERTY_LIST )
        set(_PRC_VAR_NAME ${PREFIX}_${_prc_prop})
        unset(${_PRC_VAR_NAME})
    endforeach()
    unset(_PRC_VAR_NAME)
    unset(_prc_prop)
endmacro()

#[===[.rst:
.. cmake:command:: unset_translated_lists

  .. code-block:: cmake

    unset_translated_lists(_lists)

  Unset saved properties. Can be used for cleaning up the variable name space.

  Inputs:
  ``LISTVAR``
    Prefix to use for output variable names.
#]===]
macro(unset_translated_lists LISTVAR)
    foreach(_list_name IN LISTS ${LISTVAR} )
        unset(${_list_name})
    endforeach()
    unset(_list_name)
endmacro()
#[===[.rst:
.. cmake:command:: print_saved_properties

  .. code-block:: cmake

    print_saved_properties(PREFIX LIBC)

  Print the value of all target interface properties saved with the specified prefix.
  Can be used for debugging.

  Inputs:
  ``PREFIX``
    Prefix to use for output variable names.
#]===]
function(print_saved_properties)
    set(_OPTIONS_ARGS)
    set(_ONE_VALUE_ARGS PREFIX)
    set(_MULTI_VALUE_ARGS )
    cmake_parse_arguments(_MY_PARAMS "${_OPTIONS_ARGS}" "${_ONE_VALUE_ARGS}" "${_MULTI_VALUE_ARGS}" ${ARGN})

    if (NOT DEFINED _MY_PARAMS_PREFIX)
        message(FATAL_ERROR "Mandatory parameter PREFIX is not defined.")
    endif()
    string(LENGTH "${_MY_PARAMS_PREFIX}_" _PREFIX_LENGT)

    message(STATUS "Properties saved with prefix \"${_MY_PARAMS_PREFIX}\"")
    foreach(_prop IN LISTS PROPERTYCOPY_DEFAULT_PROPERTY_LIST )
        set(_VAR_NAME "${_MY_PARAMS_PREFIX}_${_prop}")
        string(SUBSTRING "${_VAR_NAME}" ${_PREFIX_LENGT} -1 _prop)
        if (NOT DEFINED ${_VAR_NAME})
            set(_value "<Not set.>")
        else()
            set(_value ${${_VAR_NAME}})
        endif()
        message(STATUS "    ${_prop}:${_value}")
    endforeach()
endfunction()

#[===[.rst:
.. cmake:command:: print_translated_lists

  .. code-block:: cmake

    print_translated_lists(PREFIX LIBC)

  Print the value of all lists translated from interface properties by calling
  translate_interface_target_properties() with TO_LISTS set.
  Can be used for debugging.

  Inputs:
  ``LIST``
    Name of list of lists set by :command:`translate_interface_target_properties`
#]===]
function(print_translated_lists)
    set(_OPTIONS_ARGS)
    set(_ONE_VALUE_ARGS LIST)
    set(_MULTI_VALUE_ARGS )
    cmake_parse_arguments(_MY_PARAMS "${_OPTIONS_ARGS}" "${_ONE_VALUE_ARGS}" "${_MULTI_VALUE_ARGS}" ${ARGN})

    if (NOT DEFINED _MY_PARAMS_LIST)
        message(FATAL_ERROR "Mandatory parameter LIST is not defined.")
    endif()

    message(STATUS "Translated lists from \"${_MY_PARAMS_LIST}\"")
    foreach(_list IN LISTS ${_MY_PARAMS_LIST})
        message(STATUS "   ${_list}=${${_list}}")
    endforeach()
endfunction()

# These properties are cmake specific and can not be translated.
# INTERFACE_COMPILE_FEATURES, INTERFACE_LINK_DEPENDS, INTERFACE_SOURCES
# LINK_INTERFACE_LIBRARIES

# Translate target property to command line switch.
function(_prc_translate)
    set(_OPTIONS_ARGS)
    set(_ONE_VALUE_ARGS PROP RES)
    set(_MULTI_VALUE_ARGS VALUE)
    cmake_parse_arguments(_MY_PARAMS "${_OPTIONS_ARGS}" "${_ONE_VALUE_ARGS}" "${_MULTI_VALUE_ARGS}" ${ARGN})

    if ("${_MY_PARAMS_VALUE}" STREQUAL "")
        set(_res "")
    else()
        if (_MY_PARAMS_PROP STREQUAL INTERFACE_INCLUDE_DIRECTORIES)
            _prc_translate_include_list("${_MY_PARAMS_VALUE}" _res)
        elseif(_MY_PARAMS_PROP STREQUAL INTERFACE_SYSTEM_INCLUDE_DIRECTORIES)
            _prc_translate_system_include_list("${_MY_PARAMS_VALUE}" _res)
        elseif(_MY_PARAMS_PROP STREQUAL INTERFACE_COMPILE_DEFINITIONS)
            _prc_translate_macro_list("${_MY_PARAMS_VALUE}" _res)
        elseif(_MY_PARAMS_PROP STREQUAL INTERFACE_COMPILE_OPTIONS)
            _prc_translate_compile_option_list("${_MY_PARAMS_VALUE}" _res)
        elseif(_MY_PARAMS_PROP STREQUAL INTERFACE_LINK_OPTIONS)
            _prc_translate_link_option_list("${_MY_PARAMS_VALUE}" _res)
        elseif(_MY_PARAMS_PROP STREQUAL INTERFACE_LINK_DIRECTORIES)
            _prc_translate_link_directory_list("${_MY_PARAMS_VALUE}" _res)
        elseif(_MY_PARAMS_PROP STREQUAL INTERFACE_LINK_LIBRARIES)
            _prc_translate_link_library_list("${_MY_PARAMS_VALUE}" _res)
        else()
            message(FATAL_ERROR "Can not translate target property \"${_MY_PARAMS_PROP}\" to global setting.")
        endif()
    endif()
    set(${_MY_PARAMS_RES} "${_res}" PARENT_SCOPE)
endfunction()

# Translate list of include directories to compiler flags.
function(_prc_translate_include_list VALUE OUT)
    if(NOT "${VALUE}" STREQUAL "")
        string(REPLACE ";" " ${CMAKE_INCLUDE_FLAG_C} " _tmp "${VALUE}")
    else()
        set(_tmp "")
    endif()
    set(${OUT} "CMAKE_C_FLAGS_INIT;${CMAKE_INCLUDE_FLAG_C} ${_tmp}" PARENT_SCOPE)
endfunction()

# Translate list of system include directories to compiler flags.
function(_prc_translate_system_include_list VALUE OUT)
    if(NOT "${VALUE}" STREQUAL "")
        string(REPLACE ";" " ${CMAKE_INCLUDE_SYSTEM_FLAG_C} " _tmp "${VALUE}")
    else()
        set(_tmp "")
    endif()
    set(${OUT} "CMAKE_C_FLAGS_INIT;${CMAKE_INCLUDE_SYSTEM_FLAG_C} ${_tmp}" PARENT_SCOPE)
endfunction()

# Translate list of C macro definitions to compiler flags.
function(_prc_translate_macro_list VALUE OUT)
    if(NOT "${VALUE}" STREQUAL "")
        string(REPLACE ";" " -D " _tmp "${VALUE}")
    else()
        set(_tmp "")
    endif()
    set(${OUT} "CMAKE_C_FLAGS_INIT;-D ${_tmp}" PARENT_SCOPE)
endfunction()

# Translate list of compilation options to compiler flags.
function(_prc_translate_compile_option_list VALUE OUT)
    if(NOT "${VALUE}" STREQUAL "")
        string(REPLACE ";" " " _tmp "${VALUE}")
    else()
        set(_tmp "")
    endif()
    set(${OUT} "CMAKE_C_FLAGS_INIT;${_tmp}" PARENT_SCOPE)
endfunction()

# Translate list of link options to linker flags.
function(_prc_translate_link_option_list VALUE OUT)
    if(NOT "${VALUE}" STREQUAL "")
        string(REPLACE ";" " " _tmp "${VALUE}")
    else()
        set(_tmp "")
    endif()
    set(${OUT} "CMAKE_EXE_LINKER_FLAGS_INIT;${_tmp}" PARENT_SCOPE)
endfunction()

# Translate list of linker search paths to linker flags.
function(_prc_translate_link_directory_list VALUE OUT)
    if(NOT "${VALUE}" STREQUAL "")
        string(REPLACE ";" " ${CMAKE_LIBRARY_PATH_FLAG} " _tmp "${VALUE}")
    else()
        set(_tmp "")
    endif()
    set(${OUT} "CMAKE_EXE_LINKER_FLAGS_INIT;${CMAKE_LIBRARY_PATH_FLAG} ${_tmp}" PARENT_SCOPE)
endfunction()

# Translate list of libraries to linker flags.
function(_prc_translate_link_library_list VALUE OUT)
    if(NOT "${VALUE}" STREQUAL "")
        string(REPLACE ";" " ${CMAKE_LINK_LIBRARY_FLAG} " _tmp "${VALUE}")
    else()
        set(_tmp "")
    endif()
    set(${OUT} "CMAKE_EXE_LINKER_FLAGS_INIT;${CMAKE_LINK_LIBRARY_FLAG} ${_tmp}" PARENT_SCOPE)
endfunction()
