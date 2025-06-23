#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_include_directories(${TGT}
	 PRIVATE
		"${CMAKE_CURRENT_LIST_DIR}"
	)

# Advertise this component as the provider of the PSA Attestation header files
set(PSA_ATTESTATION_API_INCLUDE "${CMAKE_CURRENT_LIST_DIR}" CACHE STRING "PSA Attestation API include path")
