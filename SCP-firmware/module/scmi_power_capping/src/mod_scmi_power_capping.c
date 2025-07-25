/*
 * Arm SCP/MCP Software
 * Copyright (c) 2023-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Description:
 *      SCMI power capping and monitoring protocol completer.
 */
#include "fwk_mm.h"
#include "fwk_module_idx.h"
#include "internal/scmi_power_capping_protocol.h"
#include "mod_power_capping.h"

#ifdef BUILD_HAS_SCMI_POWER_CAPPING_FAST_CHANNELS_COMMANDS
#    include "internal/scmi_power_capping.h"
#    include "internal/scmi_power_capping_fast_channels.h"
#endif

#include <fwk_module.h>

static struct mod_scmi_power_capping_power_apis power_management_apis;

#ifdef BUILD_HAS_SCMI_POWER_CAPPING_FAST_CHANNELS_COMMANDS
static const fwk_id_t mod_scmi_power_capping_event_id_fch_callback =
    FWK_ID_EVENT_INIT(
        FWK_MODULE_IDX_SCMI_POWER_CAPPING,
        SCMI_POWER_CAPPING_EVENT_IDX_FAST_CHANNELS_PROCESS);
#endif

static int scmi_power_capping_power_api_bind(
    struct mod_scmi_power_capping_power_apis *power_apis)
{
    return fwk_module_bind(
        FWK_ID_MODULE(FWK_MODULE_IDX_POWER_CAPPING),
        FWK_ID_API(FWK_MODULE_IDX_POWER_CAPPING, MOD_POWER_CAPPING_API_IDX_CAP),
        &(power_apis->power_capping_api));
}

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
static const fwk_id_t mod_scmi_power_capping_event_id_cap_pai_notify =
    FWK_ID_EVENT_INIT(
        FWK_MODULE_IDX_SCMI_POWER_CAPPING,
        SCMI_POWER_CAPPING_EVENT_IDX_CAP_PAI_NOTIFY_PROCESS);
static const fwk_id_t mod_scmi_power_capping_event_id_measurement_notify =
    FWK_ID_EVENT_INIT(
        FWK_MODULE_IDX_SCMI_POWER_CAPPING,
        SCMI_POWER_CAPPING_EVENT_IDX_MEASUREMENT_NOTIFY_PROCESS);
#endif

static int scmi_power_capping_init(
    fwk_id_t module_id,
    unsigned int element_count,
    const void *data)
{
    if (element_count == 0) {
        return FWK_E_SUPPORT;
    }

    struct mod_scmi_power_capping_context ctx = { 0 };

    ctx.power_capping_domain_ctx_table = fwk_mm_calloc(
        element_count, sizeof(struct mod_scmi_power_capping_domain_context));
    ctx.domain_count = element_count;
#ifdef BUILD_HAS_SCMI_POWER_CAPPING_STD_COMMANDS
    pcapping_protocol_init(&ctx);
#endif

#ifdef BUILD_HAS_SCMI_POWER_CAPPING_FAST_CHANNELS_COMMANDS
    pcapping_fast_channel_ctx_init(&ctx);
#endif

    return FWK_SUCCESS;
}

static int scmi_power_capping_element_init(
    fwk_id_t element_id,
    unsigned int sub_element_count,
    const void *data)
{
    const struct mod_scmi_power_capping_domain_config *config;
    unsigned int domain_idx;
#ifdef BUILD_HAS_SCMI_POWER_CAPPING_STD_COMMANDS
    int status;
#endif

    if (data == NULL) {
        return FWK_E_PARAM;
    }

    config = (const struct mod_scmi_power_capping_domain_config *)data;
    domain_idx = fwk_id_get_element_idx(element_id);

#ifdef BUILD_HAS_SCMI_POWER_CAPPING_STD_COMMANDS
    status = pcapping_protocol_domain_init(domain_idx, config);
    if (status != FWK_SUCCESS) {
        return status;
    }
#endif

#ifdef BUILD_HAS_SCMI_POWER_CAPPING_FAST_CHANNELS_COMMANDS
    pcapping_fast_channel_set_domain_config(domain_idx, config);
#endif
    return FWK_SUCCESS;
}

static int scmi_power_capping_bind(fwk_id_t id, unsigned int round)
{
    int status = FWK_E_INIT;

    if ((round == 1) || (fwk_id_is_type(id, FWK_ID_TYPE_ELEMENT))) {
        return FWK_SUCCESS;
    }
    status = scmi_power_capping_power_api_bind(&power_management_apis);
#ifdef BUILD_HAS_SCMI_POWER_CAPPING_STD_COMMANDS
    if (status != FWK_SUCCESS) {
        return status;
    }

    status = pcapping_protocol_bind();

    if (status != FWK_SUCCESS) {
        return status;
    }
    pcapping_protocol_set_power_apis(&power_management_apis);
#endif

#ifdef BUILD_HAS_SCMI_POWER_CAPPING_FAST_CHANNELS_COMMANDS
    status = pcapping_fast_channel_bind();
    if (status != FWK_SUCCESS) {
        return status;
    }
    pcapping_fast_channel_set_power_apis(&power_management_apis);
#endif
    return status;
}

static int scmi_power_capping_start(fwk_id_t id)
{
#ifdef BUILD_HAS_SCMI_POWER_CAPPING_FAST_CHANNELS_COMMANDS
    pcapping_fast_channel_start();
#endif

#ifdef BUILD_HAS_SCMI_POWER_CAPPING_STD_COMMANDS
    return pcapping_protocol_start(id);
#else
    return FWK_SUCCESS;
#endif
}

static int scmi_power_capping_process_notification(
    const struct fwk_event *event,
    struct fwk_event *resp_event)
{
#ifdef BUILD_HAS_SCMI_POWER_CAPPING_STD_COMMANDS
    return pcapping_protocol_process_fwk_notification(event);
#else
    return FWK_SUCCESS;
#endif
}

#ifdef BUILD_HAS_SCMI_POWER_CAPPING_STD_COMMANDS
static int scmi_power_capping_process_bind_request(
    fwk_id_t source_id,
    fwk_id_t target_id,
    fwk_id_t api_id,
    const void **api)
{
    if (fwk_id_is_equal(source_id, FWK_ID_MODULE(FWK_MODULE_IDX_SCMI))) {
        return pcapping_protocol_process_bind_request(api_id, api);
    }

    return FWK_E_ACCESS;
}
#endif

static int scmi_power_capping_process_event(
    const struct fwk_event *event,
    struct fwk_event *resp_event)
{
#ifdef BUILD_HAS_SCMI_POWER_CAPPING_FAST_CHANNELS_COMMANDS
    if (fwk_id_is_equal(
            event->id, mod_scmi_power_capping_event_id_fch_callback)) {
        return pcapping_fast_channel_process_event(event);
    }
#endif

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    if (fwk_id_is_equal(
            event->id, mod_scmi_power_capping_event_id_cap_pai_notify)) {
        return pcapping_protocol_process_cap_pai_notify_event(event);
    }

    if (fwk_id_is_equal(
            event->id, mod_scmi_power_capping_event_id_measurement_notify)) {
        return pcapping_protocol_process_measurements_notify_event(event);
    }
#endif
    return FWK_E_PARAM;
}

const struct fwk_module module_scmi_power_capping = {
    .type = FWK_MODULE_TYPE_PROTOCOL,
    .api_count = (unsigned int)MOD_SCMI_POWER_CAPPING_API_IDX_COUNT,
#ifdef BUILD_HAS_SCMI_POWER_CAPPING_FAST_CHANNELS_COMMANDS
    .event_count = (unsigned int)SCMI_POWER_CAPPING_EVENT_COUNT,
#endif
    .init = scmi_power_capping_init,
    .element_init = scmi_power_capping_element_init,
    .bind = scmi_power_capping_bind,
    .start = scmi_power_capping_start,
    .process_notification = scmi_power_capping_process_notification,
    .process_event = scmi_power_capping_process_event,
#ifdef BUILD_HAS_SCMI_POWER_CAPPING_STD_COMMANDS
    .process_bind_request = scmi_power_capping_process_bind_request,
#endif
};
