#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
set(TS_PLATFORM "arm/fvp/fvp_base_revc-2xaemv8a" CACHE STRING "Target platform location.")
include(../../deployment.cmake REQUIRED)
include(${TS_ROOT}/environments/opteesp/env.cmake)

project(trusted-services LANGUAGES C ASM)
add_executable(spm-test1)

set(SP_BIN_UUID_CANON "5c9edbc3-7b3a-4367-9f83-7c191ae86a37")
set(SP_FFA_UUID_CANON "${SP_BIN_UUID_CANON}")
set(SP_FFA_UUID_CANON "5c9edbc3-7b3a-4367-9f83-7c191ae86a37")
set(SP_NUMBER 1)
set(SP_HEAP_SIZE "32 * 1024" CACHE STRING "SP heap size in bytes")
set(SP_BOOT_ORDER "0" CACHE STRING "Boot order of the SP")
set(TRACE_PREFIX "SPM-TEST${SP_NUMBER}" CACHE STRING "Trace prefix")

#-------------------------------------------------------------------------------
#  Components that are spm-test specific to deployment in the opteesp
#  environment.
#-------------------------------------------------------------------------------
add_components(TARGET "spm-test${SP_NUMBER}"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"environments/opteesp"
		"components/common/fdt"
		"components/common/trace"
		"components/common/utils"
		"components/config/ramstore"
		"components/config/loader/sp"
		"components/messaging/ffa/libsp"
)

include(${TS_ROOT}/components/service/spm_test/spm_test.cmake)
