#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

# Add source files for using uart and adapting it to the platform
# uart interface.
target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/uart_adapter.c"
	"${CMAKE_CURRENT_LIST_DIR}/pl011/pl011.c"
)
