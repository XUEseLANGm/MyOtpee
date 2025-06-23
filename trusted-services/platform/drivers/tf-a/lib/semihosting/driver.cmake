#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

#-------------------------------------------------------------------------------
# Depends on the tf-a external component
#-------------------------------------------------------------------------------
set(_SEMIHOSTING_LIB_DIR "${TFA_SOURCE_DIR}/lib/semihosting")

target_sources(${TGT} PRIVATE
	"${_SEMIHOSTING_LIB_DIR}/semihosting.c"
	"${_SEMIHOSTING_LIB_DIR}/aarch64/semihosting_call.S"
)

