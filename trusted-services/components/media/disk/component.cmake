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
set(_DISK_UEFI_DIR "${TFA_SOURCE_DIR}/drivers/partition")

target_sources(${TGT} PRIVATE
	"${_DISK_UEFI_DIR}/gpt.c"
	"${_DISK_UEFI_DIR}/partition.c"
)