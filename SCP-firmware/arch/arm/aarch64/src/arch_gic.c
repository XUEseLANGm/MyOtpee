/*
 * Arm SCP/MCP Software
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <fwk_arch.h>
#include <fwk_assert.h>
#include <fwk_core.h>
#include <fwk_mmio.h>

#include <arch_helpers.h>
#include <arch_reg.h>

#include <fmw_gic.h>

#define INTERRUPT_ID_SGI_LIMIT 16
#define INTERRUPT_ID_PPI_LIMIT 32
#define INTERRUPT_ID_SPI_LIMIT 1020
#define INTERRUPT_ID_ISR_LIMIT INTERRUPT_ID_SPI_LIMIT
#define INTERRUPT_ID_INVALID   1024

enum interrupt_type {
    INTERRUPT_TYPE_SGI,
    INTERRUPT_TYPE_PPI,
    INTERRUPT_TYPE_SPI,
    INTERRUPT_TYPE_OTHER,
};

static enum interrupt_type interrupt_type_from_id(unsigned int interrupt)
{
    if (interrupt < INTERRUPT_ID_SGI_LIMIT) {
        return INTERRUPT_TYPE_SGI;
    } else if (interrupt < INTERRUPT_ID_PPI_LIMIT) {
        return INTERRUPT_TYPE_PPI;
    } else if (interrupt < INTERRUPT_ID_SPI_LIMIT) {
        return INTERRUPT_TYPE_SPI;
    } else {
        return INTERRUPT_TYPE_OTHER;
    }
}

struct isr_callback {
    union {
        void (*func)();
        void (*func_with_param)(uintptr_t);
    };
    uintptr_t param;
};

static unsigned int current_iar = INTERRUPT_ID_INVALID;
static struct isr_callback callback[INTERRUPT_ID_ISR_LIMIT] = { 0 };

static uint64_t read_icc_iar0_el1(void)
{
    return READ_SYSREG(icc_iar_el1);
}

static void write_icc_eoir0_el1(uint64_t value)
{
    return WRITE_SYSREG(icc_eoir0_el1, value);
}

void irq_global(void)
{
    struct isr_callback *entry;

    current_iar = read_icc_iar0_el1();
    if (current_iar >= INTERRUPT_ID_ISR_LIMIT) {
        return;
    }

    entry = &callback[current_iar];

    if (entry->func != NULL) {
        if (entry->param == 0) {
            entry->func();
        } else {
            entry->func_with_param(entry->param);
        }
    }

    write_icc_eoir0_el1(current_iar);
    current_iar = INTERRUPT_ID_INVALID;
}

static int global_enable(void)
{
    arch_interrupts_enable(0);

    return FWK_SUCCESS;
}

static int global_disable(void)
{
    arch_interrupts_disable();

    return FWK_SUCCESS;
}

static int is_enabled(unsigned int interrupt, bool *enabled)
{
    switch (interrupt_type_from_id(interrupt)) {
    case INTERRUPT_TYPE_SGI:
    case INTERRUPT_TYPE_PPI:
        *enabled =
            (fwk_mmio_read_32(FMW_GICR_BASE + GICR_SGI_BASE + GICR_ISENABLER0) &
             FWK_BIT(interrupt)) != 0;
        break;
    case INTERRUPT_TYPE_SPI:
        *enabled =
            (fwk_mmio_read_32(FMW_GICD_BASE + GICD_ISENABLER(interrupt / 32)) &
             FWK_BIT(interrupt % 32)) != 0;
        break;
    case INTERRUPT_TYPE_OTHER:
        return FWK_E_SUPPORT;
    }

    return FWK_SUCCESS;
}

static int enable(unsigned int interrupt)
{
    switch (interrupt_type_from_id(interrupt)) {
    case INTERRUPT_TYPE_SGI:
    case INTERRUPT_TYPE_PPI:
        fwk_mmio_write_32(
            FMW_GICR_BASE + GICR_SGI_BASE + GICR_ISENABLER0,
            FWK_BIT(interrupt));
        break;
    case INTERRUPT_TYPE_SPI:
        fwk_mmio_write_32(
            FMW_GICD_BASE + GICD_ISENABLER(interrupt / 32),
            FWK_BIT(interrupt % 32));
        break;
    case INTERRUPT_TYPE_OTHER:
        return FWK_E_SUPPORT;
    }

    return FWK_SUCCESS;
}

static int disable(unsigned int interrupt)
{
    switch (interrupt_type_from_id(interrupt)) {
    case INTERRUPT_TYPE_SGI:
    case INTERRUPT_TYPE_PPI:
        fwk_mmio_write_32(
            FMW_GICR_BASE + GICR_SGI_BASE + GICR_ICENABLER0,
            FWK_BIT(interrupt));
        break;
    case INTERRUPT_TYPE_SPI:
        fwk_mmio_write_32(
            FMW_GICD_BASE + GICD_ICENABLER(interrupt / 32),
            FWK_BIT(interrupt % 32));
        break;
    case INTERRUPT_TYPE_OTHER:
        return FWK_E_SUPPORT;
    }

    return FWK_SUCCESS;
}

static int is_pending(unsigned int interrupt, bool *pending)
{
    switch (interrupt_type_from_id(interrupt)) {
    case INTERRUPT_TYPE_SGI:
    case INTERRUPT_TYPE_PPI:
        fwk_mmio_write_32(
            FMW_GICR_BASE + GICR_SGI_BASE + GICR_ICENABLER0,
            FWK_BIT(interrupt));
        break;
    case INTERRUPT_TYPE_SPI:
        fwk_mmio_write_32(
            FMW_GICD_BASE + GICD_ICENABLER(interrupt / 32),
            FWK_BIT(interrupt % 32));
        break;
    case INTERRUPT_TYPE_OTHER:
        return FWK_E_SUPPORT;
    }

    return FWK_SUCCESS;
}

static int set_pending(unsigned int interrupt)
{
    switch (interrupt_type_from_id(interrupt)) {
    case INTERRUPT_TYPE_SGI:
    case INTERRUPT_TYPE_PPI:
        fwk_mmio_write_32(
            FMW_GICR_BASE + GICR_SGI_BASE + GICR_ISPENDR0, FWK_BIT(interrupt));
        break;
    case INTERRUPT_TYPE_SPI:
        fwk_mmio_write_32(
            FMW_GICD_BASE + GICD_ISPENDR(interrupt / 32),
            FWK_BIT(interrupt % 32));
        break;
    case INTERRUPT_TYPE_OTHER:
        return FWK_E_SUPPORT;
    }

    return FWK_SUCCESS;
}

static int clear_pending(unsigned int interrupt)
{
    switch (interrupt_type_from_id(interrupt)) {
    case INTERRUPT_TYPE_SGI:
    case INTERRUPT_TYPE_PPI:
        fwk_mmio_write_32(
            FMW_GICR_BASE + GICR_SGI_BASE + GICR_ICPENDR0, FWK_BIT(interrupt));
        break;
    case INTERRUPT_TYPE_SPI:
        fwk_mmio_write_32(
            FMW_GICD_BASE + GICD_ICPENDR(interrupt / 32),
            FWK_BIT(interrupt % 32));
        break;
    case INTERRUPT_TYPE_OTHER:
        return FWK_E_SUPPORT;
    }

    return FWK_SUCCESS;
}

static int set_isr_irq(unsigned int interrupt, void (*isr)(void))
{
    struct isr_callback *entry;

    if (interrupt >= INTERRUPT_ID_ISR_LIMIT || isr == NULL) {
        return FWK_E_PARAM;
    }

    entry = &callback[interrupt];
    entry->func = isr;
    entry->param = 0;

    return FWK_SUCCESS;
}

static int set_isr_irq_param(
    unsigned int interrupt,
    void (*isr)(uintptr_t param),
    uintptr_t parameter)
{
    struct isr_callback *entry;

    if (interrupt >= INTERRUPT_ID_ISR_LIMIT || isr == NULL || parameter == 0) {
        return FWK_E_PARAM;
    }

    entry = &callback[interrupt];
    entry->func_with_param = isr;
    entry->param = parameter;

    return FWK_SUCCESS;
}

static int set_isr_dummy(void (*isr)(void))
{
    return FWK_E_SUPPORT;
}

static int set_isr_dummy_param(
    void (*isr)(uintptr_t param),
    uintptr_t parameter)
{
    return FWK_E_SUPPORT;
}

static int get_current(unsigned int *interrupt)
{
    if (interrupt == NULL) {
        return FWK_E_PARAM;
    }

    *interrupt = current_iar;

    return FWK_SUCCESS;
}

static bool is_interrupt_context(void)
{
    return current_iar != INTERRUPT_ID_INVALID;
}

const struct fwk_arch_interrupt_driver arm_gic_driver = {
    .global_enable = global_enable,
    .global_disable = global_disable,
    .is_enabled = is_enabled,
    .enable = enable,
    .disable = disable,
    .is_pending = is_pending,
    .set_pending = set_pending,
    .clear_pending = clear_pending,
    .set_isr_irq = set_isr_irq,
    .set_isr_irq_param = set_isr_irq_param,
    .set_isr_nmi = set_isr_dummy,
    .set_isr_nmi_param = set_isr_dummy_param,
    .set_isr_fault = set_isr_dummy,
    .get_current = get_current,
    .is_interrupt_context = is_interrupt_context,
};

int arch_gic_init(const struct fwk_arch_interrupt_driver **driver)
{
    if (driver == NULL) {
        return FWK_E_PARAM;
    }

    *driver = &arm_gic_driver;

    return FWK_SUCCESS;
}
