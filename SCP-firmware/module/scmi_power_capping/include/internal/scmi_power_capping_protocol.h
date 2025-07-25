/*
 * Arm SCP/MCP Software
 * Copyright (c) 2023-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *      SCMI power capping and monitoring protocol completer support.
 */

#ifndef INTERNAL_SCMI_POWER_CAPPING_PROTOCOL_H
#define INTERNAL_SCMI_POWER_CAPPING_PROTOCOL_H

#include "fwk_event.h"
#include "fwk_id.h"
#include "internal/scmi_power_capping.h"

#include <stdint.h>

/*!
 * \addtogroup GroupModules Modules
 * \{
 */

/*!
 * \defgroup GroupSCMI_POWER_CAPPING_PROTOCOL SCMI
 *     power capping and monitoring Protocol
 * \{
 */
#define SCMI_PROTOCOL_VERSION_POWER_CAPPING UINT32_C(0x10000)

#define SCMI_POWER_CAPPING_NO_PARENT UINT32_C(0xFFFFFFFF)

#define SCMI_POWER_CAPPING_FCH_NOT_AVAIL UINT32_C(0)
#define SCMI_POWER_CAPPING_FCH_AVAIL     UINT32_C(1)

#define SCMI_POWER_CAPPING_CAP_PAI_CHANGE_NOTIF_SUP_POS     31
#define SCMI_POWER_CAPPING_POWER_MEASUREMENTS_NOTIF_SUP_POS 30
#define SCMI_POWER_CAPPING_ASYNC_SUP_POS                    29
#define SCMI_POWER_CAPPING_EXTENDED_DOM_NAME_SUP_POS        28
#define SCMI_POWER_CAPPING_CONF_SUP_POS                     27
#define SCMI_POWER_CAPPING_MONITOR_SUP_POS                  26
#define SCMI_POWER_CAPPING_PAI_CONF_SUP_POS                 25
#define SCMI_POWER_CAPPING_POWER_UNIT_POS                   24
#define SCMI_POWER_CAPPING_FAST_CHANNEL_SUP_POS             22

#define SCMI_POWER_CAPPING_AGENT_ID_PLATFORM 0u

enum scmi_power_capping_notification_id {
    SCMI_POWER_CAPPING_CAP_CHANGED,
    SCMI_POWER_CAPPING_MEASUREMENTS_CHANGED,
};

#define SET_PCAP_CONF_SUP(PCAP_CONF_SUP) \
    (PCAP_CONF_SUP << SCMI_POWER_CAPPING_CONF_SUP_POS)

#define POWER_UNIT_MASK (UINT32_C(0x3))

#define SET_PAI_CONF_SUP(PAI_CONF_SUP) \
    (PAI_CONF_SUP << SCMI_POWER_CAPPING_PAI_CONF_SUP_POS)

#define SET_POWER_UNIT(POWER_UNIT) \
    (((POWER_UNIT) & (POWER_UNIT_MASK)) << SCMI_POWER_CAPPING_POWER_UNIT_POS)

#define SCMI_POWER_CAPPING_DOMAIN_ATTRIBUTES( \
    PCAP_CONF_SUP, PAI_CONF_SUP, POWER_UNIT) \
    (SET_PCAP_CONF_SUP(PCAP_CONF_SUP) | SET_PAI_CONF_SUP(PAI_CONF_SUP) | \
     SET_POWER_UNIT(POWER_UNIT))

#define SCMI_POWER_CAPPING_DOMAIN_FCH_SUPPORT(FAST_CHNL_SUP) \
    ((FAST_CHNL_SUP) << SCMI_POWER_CAPPING_FAST_CHANNEL_SUP_POS)

#define SCMI_POWER_CAPPING_DOMAIN_CAP_PAI_CHANGE_NOTIF_SUPPORT( \
    CAP_PAI_CHANGE_NOTIF_SUP) \
    ((CAP_PAI_CHANGE_NOTIF_SUP) \
     << SCMI_POWER_CAPPING_CAP_PAI_CHANGE_NOTIF_SUP_POS)

#define SCMI_POWER_CAPPING_DOMAIN_MEASUREMENTS_NOTIF_SUPPORT( \
    MEASUREMENTS_CHANGE_NOTIF_SUP) \
    ((MEASUREMENTS_CHANGE_NOTIF_SUP) \
     << SCMI_POWER_CAPPING_POWER_MEASUREMENTS_NOTIF_SUP_POS)

#define SCMI_POWER_CAPPING_IGN_DEL_RES_FLAG_POS 0
#define SCMI_POWER_CAPPING_IGN_DEL_RES_FLAG_MASK \
    (1 << SCMI_POWER_CAPPING_IGN_DEL_RES_FLAG_POS)

#define SCMI_POWER_CAPPING_ASYNC_FLAG_POS 1
#define SCMI_POWER_CAPPING_ASYNC_FLAG_MASK \
    (1 << SCMI_POWER_CAPPING_ASYNC_FLAG_POS)

#define SCMI_POWER_CAPPING_INVALID_MASK \
    (~(SCMI_POWER_CAPPING_IGN_DEL_RES_FLAG_MASK | \
       SCMI_POWER_CAPPING_ASYNC_FLAG_MASK))

#define SCMI_POWER_CAPPING_DISABLE_CAP_VALUE ((uint32_t)0)

#define SCMI_POWER_CAPPING_PAI_RESERVED_FLAG 0u

#define UNSUPPORTED_CONFIG_PAI_VALUE 1u

/*
 * Power capping Domain attributes
 */
#define SCMI_POWER_CAPPING_DOMAIN_NAME_LEN 16

struct scmi_power_capping_domain_attributes_a2p {
    uint32_t domain_id;
};

struct scmi_power_capping_domain_attributes_p2a {
    int32_t status;
    uint32_t attributes;
    uint8_t name[SCMI_POWER_CAPPING_DOMAIN_NAME_LEN];
    uint32_t min_pai;
    uint32_t max_pai;
    uint32_t pai_step;
    uint32_t min_power_cap;
    uint32_t max_power_cap;
    uint32_t power_cap_step;
    uint32_t max_sustainable_power;
    uint32_t accuracy;
    uint32_t parent_id;
};

/*
 * Power capping get
 */
struct scmi_power_capping_cap_get_a2p {
    uint32_t domain_id;
};

struct scmi_power_capping_cap_get_p2a {
    int32_t status;
    uint32_t power_cap;
};

/*
 * Power capping set
 */
struct scmi_power_capping_cap_set_a2p {
    uint32_t domain_id;
    uint32_t flags;
    uint32_t power_cap;
};

struct scmi_power_capping_cap_set_p2a {
    int32_t status;
};

struct scmi_power_capping_cap_set_complete_p2a {
    int32_t status;
    uint32_t domain_id;
    uint32_t power_cap;
};

/*
 * PAI get
 */
struct scmi_power_capping_pai_get_a2p {
    uint32_t domain_id;
};

struct scmi_power_capping_pai_get_p2a {
    int32_t status;
    uint32_t pai;
};

/*
 * PAI set
 */
struct scmi_power_capping_pai_set_a2p {
    uint32_t domain_id;
    uint32_t flags;
    uint32_t pai;
};

struct scmi_power_capping_pai_set_p2a {
    int32_t status;
};

/*
 * Measurements get
 */
struct scmi_power_capping_measurements_get_a2p {
    uint32_t domain_id;
};

struct scmi_power_capping_measurements_get_p2a {
    int32_t status;
    uint32_t power;
    uint32_t pai;
};

/*
 * Describe fast channels
 */
struct scmi_power_capping_describe_fc_a2p {
    uint32_t domain_id;
    uint32_t message_id;
};

struct scmi_power_capping_describe_fc_p2a {
    int32_t status;
    uint32_t attributes;
    uint32_t rate_limit;
    uint32_t chan_addr_low;
    uint32_t chan_addr_high;
    uint32_t chan_size;
    uint32_t doorbell_addr_low;
    uint32_t doorbell_addr_high;
    uint32_t doorbell_set_mask_low;
    uint32_t doorbell_set_mask_high;
    uint32_t doorbell_preserve_mask_low;
    uint32_t doorbell_preserve_mask_high;
};

/*
 * Cap notify
 */
struct scmi_power_capping_cap_notify_a2p {
    uint32_t domain_id;
    uint32_t notify_enable;
};

struct scmi_power_capping_cap_notify_p2a {
    int32_t status;
};

/*
 * Cap changed
 */
struct scmi_power_capping_cap_changed_p2a {
    uint32_t agent_id;
    uint32_t domain_id;
    uint32_t cap;
    uint32_t pai;
};

/*
 * Power measurement notify
 */
struct scmi_power_capping_measurements_notify_a2p {
    uint32_t domain_id;
    uint32_t notify_enable;
    uint32_t threshold_low;
    uint32_t threshold_high;
};

struct scmi_power_capping_measurements_notify_p2a {
    int32_t status;
};

/*
 * Power measurement changed
 */
struct scmi_power_capping_measurements_changed_p2a {
    uint32_t agent_id;
    uint32_t domain_id;
    uint32_t power;
};

/*
 * Framework interface.
 */
void pcapping_protocol_init(struct mod_scmi_power_capping_context *ctx);

int pcapping_protocol_domain_init(
    uint32_t domain_idx,
    const struct mod_scmi_power_capping_domain_config *config);

int pcapping_protocol_bind(void);

int pcapping_protocol_start(fwk_id_t id);

int pcapping_protocol_process_fwk_notification(const struct fwk_event *event);

int pcapping_protocol_process_bind_request(fwk_id_t api_id, const void **api);

void pcapping_protocol_set_power_apis(
    struct mod_scmi_power_capping_power_apis *power_management_apis);

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
int pcapping_protocol_process_cap_pai_notify_event(
    const struct fwk_event *event);

int pcapping_protocol_process_measurements_notify_event(
    const struct fwk_event *event);
#endif

/*!
 * \}
 */

/*!
 * \}
 */

#endif /* INTERNAL_SCMI_POWER_CAPPING_PROTOCOL_H */
