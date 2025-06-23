#-------------------------------------------------------------------------------
# Copyright (c) 2021-2024, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

# Add source files for using mhu driver
target_sources(${TGT}
	PRIVATE
		"${CMAKE_CURRENT_LIST_DIR}/mhu_v2_x.c"
		"${CMAKE_CURRENT_LIST_DIR}/mhu_wrapper_v2_x.c"
		"${CMAKE_CURRENT_LIST_DIR}/mhu_adapter_v2_x.c"
)
