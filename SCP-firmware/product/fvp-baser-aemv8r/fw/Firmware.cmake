#
# Arm SCP/MCP Software
# Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

set(SCP_FIRMWARE "fvp-baser-aemv8r")
set(SCP_FIRMWARE_TARGET "fvp-baser-aemv8r")

set(SCP_TOOLCHAIN_INIT "GNU")

set(SCP_GENERATE_FLAT_BINARY_INIT TRUE)

set(SCP_ARCHITECTURE "aarch64")

list(APPEND SCP_MODULES
    "armv8r-mpu"
    "pl011"
    "gicx00"
    "sp805"
)
