#-------------------------------------------------------------------------------
# Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
include($ENV{TS_BASE_TOOLCHAIN_FILE} REQUIRED)

set(CMAKE_POSITION_INDEPENDENT_CODE True)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

# Hide symbols from libraries statically linked to the shared library
add_link_options(-Wl,--exclude-libs,ALL)
