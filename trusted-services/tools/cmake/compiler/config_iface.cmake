#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

# This provides a common interface for injecting definitions and include paths
# into a cmake build for the purpose of applying an externally defined
# build configuration.  Although some cmake based external components provide
# their own cmake based configuration interface, not all do.  This file gets
# included by environment specific cmake toolchain files that get actioned
# early on when a new cmake build context is created.
add_definitions(${EXTERNAL_DEFINITIONS})
include_directories(${EXTERNAL_INCLUDE_PATHS})
