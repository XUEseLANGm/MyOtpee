#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

set(_DRIVER_DIR "${EDK2_PLATFORMS_PATH}/Platform/ARM/Morello/Drivers/CadenceQspiDxe")

target_sources(${TGT} PRIVATE
	"${_DRIVER_DIR}/CadenceQspiDxe.c"
	"${_DRIVER_DIR}/NorFlash.c"
	"${_DRIVER_DIR}/NorFlashFvb.c"
)

