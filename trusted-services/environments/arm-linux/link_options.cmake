#-------------------------------------------------------------------------------
# Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#[===[.rst:
.. cmake:command:: env_set_link_options

  .. code-block:: cmake

	 env_set_link_options(TGT foo)

  Set default compile options for the arm-linux environment.

  Inputs:

   ``TGT``
    Name of target to compile generated source files.

#]===]
function(env_set_link_options)
    set(_options )
    set(_oneValueArgs TGT)
    set(_multiValueArgs )

    cmake_parse_arguments(PARAMS "${_options}" "${_oneValueArgs}" "${_multiValueArgs}" ${ARGN})

    #Verify mandatory parameters
    if (NOT DEFINED PARAMS_TGT)
        message(FATAL_ERROR "env_set_link_options(): mandatory parameter TGT missing.")
    endif()

    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        # Options for GCC that control linking
        target_link_options(${PARAMS_TGT} PRIVATE
            -fno-lto
            -pie
            -zmax-page-size=4096
        )
        # Options directly for LD, these are not understood by GCC
        target_link_options(${PARAMS_TGT} PRIVATE
            -Wl,--as-needed
            -Wl,--sort-section=alignment
            # -Wl,--dynamic-list ${CMAKE_CURRENT_LIST_DIR}/dyn_list
        )
    endif()

endfunction()
