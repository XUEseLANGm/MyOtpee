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
# Depends on the tf-a external component. The base io_dev interface is realized
# by the following tf-a files.
#-------------------------------------------------------------------------------
target_sources(${TGT} PRIVATE
	"${TFA_SOURCE_DIR}/drivers/io/io_storage.c"
)