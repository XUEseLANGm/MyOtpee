#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

# Add source files for using juno_trng and adapting it to the platform
# trng interface.
target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/juno_trng.c"
	"${CMAKE_CURRENT_LIST_DIR}/juno_trng_adapter.c"
)
