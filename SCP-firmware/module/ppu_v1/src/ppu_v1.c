/*
 * Arm SCP/MCP Software
 * Copyright (c) 2015-2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ppu_v1.h"

#include <fwk_assert.h>
#include <fwk_status.h>

#include <stddef.h>

#define PPU_V1_WRITE_PPU_REG(ppu, reg, value) \
    (ppu_v1_write_ppu_reg(ppu, &ppu->ppu_reg->reg, value))

struct set_power_status_check_params_v1 {
    enum ppu_v1_mode mode;
    struct ppu_v1_regs *reg;
};

static bool ppu_v1_set_power_status_check(void *data)
{
    struct set_power_status_check_params_v1 *params;

    fwk_assert(data != NULL);
    params = (struct set_power_status_check_params_v1 *)data;

    return (
        (params->reg->ppu_reg->PWSR &
         (PPU_V1_PWSR_PWR_STATUS | PPU_V1_PWSR_PWR_DYN_STATUS)) ==
        params->mode);
}

static inline void ppu_v1_write_ppu_reg(
    struct ppu_v1_regs *ppu,
    FWK_W uint32_t *ppu_reg,
    uint32_t value)
{
#ifdef BUILD_HAS_AE_EXTENSION
    if (ppu->cluster_ae_reg != NULL) {
        ppu->cluster_ae_reg->CLUSTERWRITEKEY = CLUSTER_AE_KEY_VALUE;
    }
#endif
    *ppu_reg = value;
}

void ppu_v1_init(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    /* Set edge sensitivity to masked for all input edges */
    PPU_V1_WRITE_PPU_REG(ppu, IESR, 0);

    /* Mask all interrupts */
    PPU_V1_WRITE_PPU_REG(ppu, IMR, PPU_V1_IMR_MASK);

    /* Acknowledge any interrupt left pending */
    PPU_V1_WRITE_PPU_REG(ppu, ISR, PPU_V1_ISR_MASK);
}

/*
 * PWPR and PWSR registers
 */
int ppu_v1_request_power_mode(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_mode ppu_mode)
{
    uint32_t power_policy;
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);
    fwk_assert(ppu_mode < PPU_V1_MODE_COUNT);

    power_policy =
        ppu->ppu_reg->PWPR & ~(PPU_V1_PWPR_POLICY | PPU_V1_PWPR_DYNAMIC_EN);
    PPU_V1_WRITE_PPU_REG(ppu, PWPR, power_policy | ppu_mode);

    return FWK_SUCCESS;
}

int ppu_v1_set_power_mode(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_mode ppu_mode,
    struct ppu_v1_timer_ctx *timer_ctx)
{
    int status;
    struct set_power_status_check_params_v1 params;

    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    status = ppu_v1_request_power_mode(ppu, ppu_mode);
    if (status != FWK_SUCCESS)
        return status;

    if (timer_ctx == NULL) {
        while ((ppu->ppu_reg->PWSR &
                (PPU_V1_PWSR_PWR_STATUS | PPU_V1_PWSR_PWR_DYN_STATUS)) !=
               ppu_mode)
            continue;
    } else {
        params.mode = ppu_mode;
        params.reg = ppu;
        return timer_ctx->timer_api->wait(
            timer_ctx->timer_id,
            timer_ctx->delay_us,
            ppu_v1_set_power_status_check,
            &params);
    }

    return FWK_SUCCESS;
}

int ppu_v1_request_operating_mode(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_opmode op_mode)
{
    uint32_t power_policy;
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);
    fwk_assert(op_mode < PPU_V1_OPMODE_COUNT);

    power_policy =
        ppu->ppu_reg->PWPR & ~(PPU_V1_PWPR_OP_POLICY | PPU_V1_PWPR_OP_DYN_EN);
    PPU_V1_WRITE_PPU_REG(
        ppu, PWPR, power_policy | (op_mode << PPU_V1_PWPR_OP_POLICY_POS));

    return FWK_SUCCESS;
}

void ppu_v1_opmode_dynamic_enable(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_opmode min_dyn_mode)
{
    uint32_t power_policy;

    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);
    fwk_assert(min_dyn_mode < PPU_V1_OPMODE_COUNT);

    power_policy = ppu->ppu_reg->PWPR & ~PPU_V1_PWPR_OP_POLICY;
    PPU_V1_WRITE_PPU_REG(
        ppu,
        PWPR,
        power_policy | PPU_V1_PWPR_OP_DYN_EN |
            (min_dyn_mode << PPU_V1_PWPR_OP_POLICY_POS));
    while ((ppu->ppu_reg->PWSR & PPU_V1_PWSR_OP_DYN_STATUS) == 0)
        continue;
}

void ppu_v1_dynamic_enable(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_mode min_dyn_state)
{
    uint32_t power_policy;

    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);
    fwk_assert(min_dyn_state < PPU_V1_MODE_COUNT);

    power_policy = ppu->ppu_reg->PWPR & ~PPU_V1_PWPR_POLICY;
    PPU_V1_WRITE_PPU_REG(
        ppu, PWPR, power_policy | PPU_V1_PWPR_DYNAMIC_EN | min_dyn_state);
    while ((ppu->ppu_reg->PWSR & PPU_V1_PWSR_PWR_DYN_STATUS) == 0)
        continue;
}

void ppu_v1_lock_off_enable(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, PWPR, ppu->ppu_reg->PWPR | PPU_V1_PWPR_OFF_LOCK_EN);
}

void ppu_v1_lock_off_disable(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, PWPR, ppu->ppu_reg->PWPR & ~PPU_V1_PWPR_OFF_LOCK_EN);
}

enum ppu_v1_mode ppu_v1_get_power_mode(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return (enum ppu_v1_mode)(ppu->ppu_reg->PWSR & PPU_V1_PWSR_PWR_STATUS);
}

enum ppu_v1_mode ppu_v1_get_programmed_power_mode(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return (enum ppu_v1_mode)(ppu->ppu_reg->PWPR & PPU_V1_PWPR_POLICY);
}

enum ppu_v1_opmode ppu_v1_get_operating_mode(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return (enum ppu_v1_opmode)(
        (ppu->ppu_reg->PWSR & PPU_V1_PWSR_OP_STATUS) >>
        PPU_V1_PWSR_OP_STATUS_POS);
}

enum ppu_v1_opmode ppu_v1_get_programmed_operating_mode(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return (enum ppu_v1_opmode)(
        (ppu->ppu_reg->PWPR & PPU_V1_PWPR_OP_POLICY) >>
        PPU_V1_PWPR_OP_POLICY_POS);
}

bool ppu_v1_is_dynamic_enabled(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return ((ppu->ppu_reg->PWSR & PPU_V1_PWSR_PWR_DYN_STATUS) != 0);
}

bool ppu_v1_is_locked(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return ((ppu->ppu_reg->PWSR & PPU_V1_PWSR_OFF_LOCK_STATUS) != 0);
}

/*
 * DISR register
 */
bool ppu_v1_is_power_devactive_high(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_mode ppu_mode)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return (ppu->ppu_reg->DISR &
            (1 << (ppu_mode + PPU_V1_DISR_PWR_DEVACTIVE_STATUS_POS))) != 0;
}

bool ppu_v1_is_op_devactive_high(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_op_devactive op_devactive)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return (ppu->ppu_reg->DISR &
            (1 << (op_devactive + PPU_V1_DISR_OP_DEVACTIVE_STATUS_POS))) != 0;
}

/*
 * UNLK register
 */
void ppu_v1_off_unlock(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(ppu, UNLK, PPU_V1_UNLK_OFF_UNLOCK);
}

/*
 * PWCR register
 */
void ppu_v1_disable_devactive(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, PWCR, ppu->ppu_reg->PWCR & ~PPU_V1_PWCR_DEV_ACTIVE_EN);
}

void ppu_v1_disable_handshake(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, PWCR, ppu->ppu_reg->PWCR & ~PPU_V1_PWCR_DEV_REQ_EN);
}

/*
 * Interrupt registers: IMR, AIMR, ISR, AISR, IESR, OPSR
 */
void ppu_v1_interrupt_mask(struct ppu_v1_regs *ppu, unsigned int mask)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, IMR, ppu->ppu_reg->IMR | (mask & PPU_V1_IMR_MASK));
}

void ppu_v1_additional_interrupt_mask(
    struct ppu_v1_regs *ppu,
    unsigned int mask)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, AIMR, ppu->ppu_reg->AIMR | (mask & PPU_V1_AIMR_MASK));
}

void ppu_v1_interrupt_unmask(struct ppu_v1_regs *ppu, unsigned int mask)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, IMR, ppu->ppu_reg->IMR & ~(mask & PPU_V1_IMR_MASK));
}

void ppu_v1_additional_interrupt_unmask(
    struct ppu_v1_regs *ppu,
    unsigned int mask)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, AIMR, ppu->ppu_reg->AIMR & ~(mask & PPU_V1_AIMR_MASK));
}

bool ppu_v1_is_additional_interrupt_pending(
    struct ppu_v1_regs *ppu,
    unsigned int mask)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return (ppu->ppu_reg->AISR & (mask & PPU_V1_AISR_MASK)) != 0;
}

void ppu_v1_ack_interrupt(struct ppu_v1_regs *ppu, unsigned int mask)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(ppu, ISR, ppu->ppu_reg->ISR & mask & PPU_V1_IMR_MASK);
}

void ppu_v1_ack_additional_interrupt(struct ppu_v1_regs *ppu, unsigned int mask)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, AISR, ppu->ppu_reg->AISR & mask & PPU_V1_AIMR_MASK);
}

void ppu_v1_set_input_edge_sensitivity(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_mode ppu_mode,
    enum ppu_v1_edge_sensitivity edge_sensitivity)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);
    fwk_assert(ppu_mode < PPU_V1_MODE_COUNT);
    fwk_assert((edge_sensitivity & ~PPU_V1_EDGE_SENSITIVITY_MASK) == 0);

    /* Clear current settings */
    PPU_V1_WRITE_PPU_REG(
        ppu,
        IESR,
        ppu->ppu_reg->IESR &
            ~(PPU_V1_EDGE_SENSITIVITY_MASK
              << (ppu_mode * PPU_V1_BITS_PER_EDGE_SENSITIVITY)));

    /* Update settings */
    PPU_V1_WRITE_PPU_REG(
        ppu,
        IESR,
        ppu->ppu_reg->IESR |
            edge_sensitivity << (ppu_mode * PPU_V1_BITS_PER_EDGE_SENSITIVITY));
}

enum ppu_v1_edge_sensitivity ppu_v1_get_input_edge_sensitivity(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_mode ppu_mode)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);
    fwk_assert(ppu_mode < PPU_V1_MODE_COUNT);

    return (enum ppu_v1_edge_sensitivity)(
        (ppu->ppu_reg->IESR >> (ppu_mode * PPU_V1_BITS_PER_EDGE_SENSITIVITY)) &
        PPU_V1_EDGE_SENSITIVITY_MASK);
}

void ppu_v1_ack_power_active_edge_interrupt(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_mode ppu_mode)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, ISR, 1 << (ppu_mode + PPU_V1_ISR_ACTIVE_EDGE_POS));
}

bool ppu_v1_is_power_active_edge_interrupt(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_mode ppu_mode)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return ppu->ppu_reg->ISR & (1 << (ppu_mode + PPU_V1_ISR_ACTIVE_EDGE_POS));
}

void ppu_v1_set_op_active_edge_sensitivity(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_op_devactive op_devactive,
    enum ppu_v1_edge_sensitivity edge_sensitivity)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);
    fwk_assert(op_devactive < PPU_V1_OP_DEVACTIVE_COUNT);
    fwk_assert((edge_sensitivity & ~PPU_V1_EDGE_SENSITIVITY_MASK) == 0);

    /* Clear current settings */
    PPU_V1_WRITE_PPU_REG(
        ppu,
        OPSR,
        ppu->ppu_reg->OPSR &
            ~(PPU_V1_EDGE_SENSITIVITY_MASK
              << (op_devactive * PPU_V1_BITS_PER_EDGE_SENSITIVITY)));

    /* Update settings */
    PPU_V1_WRITE_PPU_REG(
        ppu,
        OPSR,
        ppu->ppu_reg->OPSR |
            edge_sensitivity
                << (op_devactive * PPU_V1_BITS_PER_EDGE_SENSITIVITY));
}

enum ppu_v1_edge_sensitivity ppu_v1_get_op_active_edge_sensitivity(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_op_devactive op_devactive)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);
    fwk_assert(op_devactive < PPU_V1_OP_DEVACTIVE_COUNT);

    return (enum ppu_v1_edge_sensitivity)(
        (ppu->ppu_reg->OPSR >>
         (op_devactive * PPU_V1_BITS_PER_EDGE_SENSITIVITY)) &
        PPU_V1_EDGE_SENSITIVITY_MASK);
}

void ppu_v1_ack_op_active_edge_interrupt(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_op_devactive op_devactive)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    PPU_V1_WRITE_PPU_REG(
        ppu, ISR, 1 << (op_devactive + PPU_V1_ISR_OP_ACTIVE_EDGE_POS));
}

bool ppu_v1_is_op_active_edge_interrupt(
    struct ppu_v1_regs *ppu,
    enum ppu_v1_op_devactive op_devactive)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return ppu->ppu_reg->ISR &
        (1 << (op_devactive + PPU_V1_ISR_OP_ACTIVE_EDGE_POS));
}

bool ppu_v1_is_dyn_policy_min_interrupt(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return ppu->ppu_reg->ISR & PPU_V1_ISR_DYN_POLICY_MIN_IRQ;
}

/*
 * IDR0 register
 */
unsigned int ppu_v1_get_num_opmode(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return ((ppu->ppu_reg->IDR0 & PPU_V1_IDR0_NUM_OPMODE) >>
            PPU_V1_IDR0_NUM_OPMODE_POS) +
        1;
}

/*
 * AIDR register
 */
unsigned int ppu_v1_get_arch_id(struct ppu_v1_regs *ppu)
{
    fwk_assert(ppu != NULL);
    fwk_assert(ppu->ppu_reg != NULL);

    return (
        ppu->ppu_reg->AIDR &
        (PPU_V1_AIDR_ARCH_REV_MINOR | PPU_V1_AIDR_ARCH_REV_MAJOR));
}
