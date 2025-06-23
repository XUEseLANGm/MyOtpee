/*
 * Arm SCP/MCP Software
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "unity.h"

#include <ppu_v1.h>

#include UNIT_TEST_SRC

#define WRITE_PATTERN 0x11223344

void setUp(void)
{
}

void tearDown(void)
{
}

#ifdef BUILD_HAS_AE_EXTENSION
void test_ppu_v1_write_ppu_reg(void)
{
    struct ppu_v1_regs ppu;
    struct ppu_v1_ppu_reg ppu_reg;
    struct ppu_v1_cluster_ae_reg cluster_ae_reg;

    ppu.ppu_reg = &ppu_reg;
    ppu.cluster_ae_reg = &cluster_ae_reg;
    ppu_reg.PWPR = 0;
    cluster_ae_reg.CLUSTERWRITEKEY = 0;

    ppu_v1_write_ppu_reg(&ppu, &ppu_reg.PWPR, WRITE_PATTERN);
    TEST_ASSERT_EQUAL(ppu_reg.PWPR, WRITE_PATTERN);
    TEST_ASSERT_EQUAL(cluster_ae_reg.CLUSTERWRITEKEY, CLUSTER_AE_KEY_VALUE);
}
#else
void test_ppu_v1_write_ppu_reg(void)
{
    struct ppu_v1_regs ppu;
    struct ppu_v1_ppu_reg ppu_reg;

    ppu.ppu_reg = &ppu_reg;
    ppu_reg.PWPR = 0;

    ppu_v1_write_ppu_reg(&ppu, &ppu_reg.PWPR, WRITE_PATTERN);
    TEST_ASSERT_EQUAL(ppu_reg.PWPR, WRITE_PATTERN);
}
#endif

int ppu_v1_test_main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_ppu_v1_write_ppu_reg);

    return UNITY_END();
}

int main(void)
{
    return ppu_v1_test_main();
}
