#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

set(_DRIVER_DIR "${TFA_SOURCE_DIR}/drivers/cfi/v2m")

target_sources(${TGT} PRIVATE
	"${_DRIVER_DIR}/v2m_flash.c"
)

