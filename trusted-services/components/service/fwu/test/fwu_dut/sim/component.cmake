#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/sim_fwu_dut.cpp"
	)

#-------------------------------------------------------------------------------
#  Override TF-A defaults to increase number of io devices to accommodate
#  the needs of the sim_fwu_dut.
#-------------------------------------------------------------------------------
target_compile_definitions(${TGT} PRIVATE
MAX_IO_HANDLES=12
MAX_IO_DEVICES=12
)