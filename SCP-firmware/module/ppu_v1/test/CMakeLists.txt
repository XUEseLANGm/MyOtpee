#
# Arm SCP/MCP Software
# Copyright (c) 2023-2024, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

################################################################################
# Test ppu_v1.c without BUILD_HAS_AE_EXTENSION                                 #
################################################################################
set(TEST_SRC ppu_v1)
set(TEST_FILE ppu_v1)

set(UNIT_TEST_TARGET ${TEST_MODULE}_unit_test)

set(MODULE_SRC ${MODULE_ROOT}/${TEST_MODULE}/src)
set(MODULE_INC ${MODULE_ROOT}/${TEST_MODULE}/include)
list(APPEND OTHER_MODULE_INC ${MODULE_ROOT}/power_domain/include)
list(APPEND OTHER_MODULE_INC ${MODULE_ROOT}/timer/include)
set(MODULE_UT_SRC ${CMAKE_CURRENT_LIST_DIR})

list(APPEND MOCK_REPLACEMENTS fwk_module)

include(${SCP_ROOT}/unit_test/module_common.cmake)

################################################################################
# Test ppu_v1.c with BUILD_HAS_AE_EXTENSION                                    #
################################################################################
set(TEST_SRC ppu_v1)
set(TEST_FILE ppu_v1)

set(UNIT_TEST_TARGET ${TEST_MODULE}_unit_test_ae)

set(MODULE_SRC ${MODULE_ROOT}/${TEST_MODULE}/src)
set(MODULE_INC ${MODULE_ROOT}/${TEST_MODULE}/include)
list(APPEND OTHER_MODULE_INC ${MODULE_ROOT}/power_domain/include)
list(APPEND OTHER_MODULE_INC ${MODULE_ROOT}/timer/include)
set(MODULE_UT_SRC ${CMAKE_CURRENT_LIST_DIR})

list(APPEND MOCK_REPLACEMENTS fwk_module)

include(${SCP_ROOT}/unit_test/module_common.cmake)

target_compile_definitions(${UNIT_TEST_TARGET}
        PUBLIC "BUILD_HAS_AE_EXTENSION")

################################################################################
# Test mod_ppu_v1.c                                                            #
################################################################################
set(TEST_SRC mod_ppu_v1)
set(TEST_FILE mod_ppu_v1)

set(UNIT_TEST_TARGET mod_${TEST_MODULE}_unit_test)

set(MODULE_SRC ${MODULE_ROOT}/${TEST_MODULE}/src)
set(MODULE_INC ${MODULE_ROOT}/${TEST_MODULE}/include)
list(APPEND OTHER_MODULE_INC ${MODULE_ROOT}/scmi/include)
list(APPEND OTHER_MODULE_INC ${MODULE_ROOT}/power_domain/include)
list(APPEND OTHER_MODULE_INC ${MODULE_ROOT}/timer/include)
set(MODULE_UT_SRC ${CMAKE_CURRENT_LIST_DIR})
set(MODULE_UT_INC ${CMAKE_CURRENT_LIST_DIR})
set(MODULE_UT_MOCK_SRC ${CMAKE_CURRENT_LIST_DIR}/mocks)

list(APPEND MOCK_REPLACEMENTS fwk_module)
list(APPEND MOCK_REPLACEMENTS fwk_mm)
list(APPEND MOCK_REPLACEMENTS fwk_id)
list(APPEND MOCK_REPLACEMENTS fwk_core)
list(APPEND MOCK_REPLACEMENTS fwk_notification)

include(${SCP_ROOT}/unit_test/module_common.cmake)

target_compile_definitions(${UNIT_TEST_TARGET}
        PUBLIC "BUILD_HAS_MOD_POWER_DOMAIN")

target_compile_definitions(${UNIT_TEST_TARGET}
        PUBLIC "BUILD_HAS_MOD_TIMER")
