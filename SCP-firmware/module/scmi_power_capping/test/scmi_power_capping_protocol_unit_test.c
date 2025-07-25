/*
 * Arm SCP/MCP Software
 * Copyright (c) 2023-2025, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "scp_unity.h"
#include "string.h"
#include "unity.h"

#include <Mockfwk_id.h>
#include <Mockfwk_mm.h>
#include <Mockfwk_module.h>
#include <Mockfwk_notification.h>
#include <Mockmod_power_capping_extra.h>
#include <Mockmod_resource_perms_extra.h>
#include <Mockmod_scmi_extra.h>
#include <internal/Mockfwk_core_internal.h>

#include <mod_scmi_power_capping_unit_test.h>

#include <stdarg.h>

#include UNIT_TEST_SRC

#define EXPECT_RESPONSE(ret_payload, ret_payload_size) \
    respond_ExpectWithArrayAndReturn( \
        service_id_1, \
        (void *)&ret_payload, \
        ret_payload_size, \
        ret_payload_size, \
        FWK_SUCCESS)

#define EXPECT_RESPONSE_SUCCESS(ret_payload) \
    EXPECT_RESPONSE(ret_payload, sizeof(ret_payload))

#define EXPECT_RESPONSE_ERROR(ret_payload) \
    EXPECT_RESPONSE(ret_payload, sizeof(ret_payload.status))

#define TEST_SCMI_COMMAND_NO_PAYLOAD(message_id) \
    do { \
        status = scmi_power_capping_message_handler( \
            dummy_protocol_id, \
            service_id_1, \
            (void *)&dummy_protocol_id, \
            0, \
            message_id); \
        TEST_ASSERT_EQUAL(status, FWK_SUCCESS); \
    } while (0)

#define TEST_SCMI_COMMAND(message_id, cmd_payload) \
    do { \
        status = scmi_power_capping_message_handler( \
            dummy_protocol_id, \
            service_id_1, \
            (void *)&cmd_payload, \
            sizeof(cmd_payload), \
            message_id); \
        TEST_ASSERT_EQUAL(status, FWK_SUCCESS); \
    } while (0)

#define RESOURCE_PERMISSION_RESOURCE_PASS_TEST() \
    do { \
        get_agent_id_ExpectAnyArgsAndReturn(FWK_SUCCESS); \
        agent_has_resource_permission_ExpectAnyArgsAndReturn( \
            MOD_RES_PERMS_ACCESS_ALLOWED); \
    } while (0)

#define RESOURCE_PERMISSION_PROTOCOL_PASS_TEST() \
    do { \
        get_agent_id_ExpectAnyArgsAndReturn(FWK_SUCCESS); \
        agent_has_protocol_permission_ExpectAnyArgsAndReturn( \
            MOD_RES_PERMS_ACCESS_ALLOWED); \
    } while (0)

static int status;

static const struct mod_scmi_from_protocol_api scmi_api = {
    .respond = respond,
    .get_agent_id = get_agent_id,
    .get_agent_count = get_agent_count,
    .scmi_message_validation = mod_scmi_from_protocol_api_scmi_frame_validation,
};

static const struct mod_power_capping_api power_capping_api = {
    .get_applied_cap = get_applied_cap,
    .request_cap = request_cap,
    .get_average_power = get_average_power,
    .get_averaging_interval = get_averaging_interval,
    .get_averaging_interval_range = get_averaging_interval_range,
    .get_averaging_interval_step = get_averaging_interval_step,
    .set_averaging_interval = set_averaging_interval,
};

#ifdef BUILD_HAS_MOD_RESOURCE_PERMS
static const struct mod_res_permissions_api res_perms_api = {
    .agent_has_protocol_permission = agent_has_protocol_permission,
    .agent_has_resource_permission = agent_has_resource_permission,
};
#endif

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
static const struct mod_scmi_notification_api scmi_notification_api = {
    .scmi_notification_init = scmi_notification_init,
    .scmi_notification_add_subscriber = scmi_notification_add_subscriber,
    .scmi_notification_remove_subscriber = scmi_notification_remove_subscriber,
    .scmi_notification_notify = scmi_notification_notify,
};
#endif

static const struct mod_scmi_power_capping_power_apis power_management_apis = {
    .power_capping_api = &power_capping_api,
};

static fwk_id_t service_id_1 =
    FWK_ID_ELEMENT_INIT(FAKE_SCMI_MODULE_ID, FAKE_SERVICE_IDX_1);
static fwk_id_t dummy_protocol_id;
static uint32_t dummy_payload;

static const struct mod_scmi_power_capping_domain_config
    scmi_power_capping_default_config = {
        .parent_idx = __LINE__,
        .power_capping_domain_id =
            FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_POWER_CAPPING, __LINE__),
#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
        .cap_pai_change_notification_support = true,
#endif
        .min_power_cap = MIN_DEFAULT_POWER_CAP,
        .max_power_cap = MAX_DEFAULT_POWER_CAP,
        .power_cap_step = 1,
        .pai_config_support = true,
    };

static const struct mod_scmi_power_capping_domain_config
    scmi_power_capping_config_1 = {
        .parent_idx = __LINE__,
        .power_capping_domain_id =
            FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_POWER_CAPPING, __LINE__),
        .min_power_cap = MIN_DEFAULT_POWER_CAP,
        .max_power_cap = MIN_DEFAULT_POWER_CAP,
        .pai_config_support = true,
    };

static struct mod_scmi_power_capping_domain_context
    domain_ctx_table[FAKE_POWER_CAPPING_IDX_COUNT];

/* Helper functions */
static void test_set_domain_cap_pending_service_id(
    unsigned int domain_idx,
    fwk_id_t service_id)
{
    domain_ctx_table[domain_idx].cap_pending_service_id = service_id;
}

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
static void test_set_domain_cap_notification_service_id(
    unsigned int domain_idx,
    fwk_id_t service_id)
{
    domain_ctx_table[domain_idx].cap_notification_service_id = service_id;
}

static void test_set_domain_pai_notification_service_id(
    unsigned int domain_idx,
    fwk_id_t service_id)
{
    domain_ctx_table[domain_idx].pai_notification_service_id = service_id;
}
#endif

static void test_request_cap_config_supported(
    unsigned int domain_idx,
    bool cap_config_supported)
{
    domain_ctx_table[domain_idx].cap_config_support = cap_config_supported;
}

/* Test functions */
/* Initialize the tests */
static void test_init(void)
{
    pcapping_protocol_ctx.scmi_api = &scmi_api;
#ifdef BUILD_HAS_MOD_RESOURCE_PERMS
    pcapping_protocol_ctx.res_perms_api = &res_perms_api;
#endif

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    pcapping_protocol_ctx.scmi_notification_api = &scmi_notification_api;
#endif
    pcapping_protocol_ctx.power_management_apis = &power_management_apis;
    pcapping_protocol_ctx.power_capping_domain_count =
        FAKE_POWER_CAPPING_IDX_COUNT;
}

void setUp(void)
{
    status = FWK_E_STATE;
    pcapping_protocol_ctx.power_capping_domain_ctx_table = domain_ctx_table;
    memset(domain_ctx_table, 0u, sizeof(domain_ctx_table));
    for (unsigned int domain_id = 0; domain_id < FAKE_POWER_CAPPING_IDX_COUNT;
         domain_id++) {
        domain_ctx_table[domain_id].config = &scmi_power_capping_default_config;
        test_set_domain_cap_pending_service_id(domain_id, FWK_ID_NONE);
#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
        test_set_domain_cap_notification_service_id(domain_id, FWK_ID_NONE);
        test_set_domain_pai_notification_service_id(domain_id, FWK_ID_NONE);
#endif
    }
    pcapping_protocol_ctx.power_capping_domain_count =
        FAKE_POWER_CAPPING_IDX_COUNT;
}

void tearDown(void)
{
    Mockmod_power_capping_extra_Verify();
    Mockmod_scmi_extra_Verify();
    Mockfwk_id_Verify();
#ifdef BUILD_HAS_MOD_RESOURCE_PERMS
    Mockmod_resource_perms_extra_Verify();
#endif
}

void utest_get_scmi_protocol_id(void)
{
    uint8_t scmi_protocol_id;

    status = scmi_power_capping_get_scmi_protocol_id(
        dummy_protocol_id, &scmi_protocol_id);

    TEST_ASSERT_EQUAL(scmi_protocol_id, MOD_SCMI_PROTOCOL_ID_POWER_CAPPING);
    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
}

void utest_message_handler_cmd_error(void)
{
    struct scmi_protocol_version_p2a ret_payload = {
        .status = SCMI_PROTOCOL_ERROR,
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_PROTOCOL_ERROR);
    EXPECT_RESPONSE_ERROR(ret_payload);
    /* Add payload to a command that normally doesn't expect a payload */
    TEST_SCMI_COMMAND(MOD_SCMI_PROTOCOL_VERSION, dummy_payload);
}

void utest_message_handler_invalid_cmd(void)
{
    struct scmi_protocol_version_p2a ret_payload = {
        .status = SCMI_NOT_FOUND,
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_NOT_FOUND);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND_NO_PAYLOAD(MOD_SCMI_POWER_CAPPING_COMMAND_COUNT);
}

void utest_message_handler_un_implemented_message(void)
{
    int (*temp_handle)(fwk_id_t, const uint32_t *);
    struct scmi_protocol_version_p2a ret_payload = {
        .status = SCMI_NOT_SUPPORTED,
    };

    temp_handle = handler_table[MOD_SCMI_PROTOCOL_VERSION];
    handler_table[MOD_SCMI_PROTOCOL_VERSION] = NULL;

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_NOT_SUPPORTED);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND_NO_PAYLOAD(MOD_SCMI_PROTOCOL_VERSION);

    handler_table[MOD_SCMI_PROTOCOL_VERSION] = temp_handle;
}

void utest_message_handler_protocol_version(void)
{
    struct scmi_protocol_version_p2a ret_payload = {
        .status = SCMI_SUCCESS,
        .version = SCMI_PROTOCOL_VERSION_POWER_CAPPING,
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND_NO_PAYLOAD(MOD_SCMI_PROTOCOL_VERSION);
}

void utest_message_handler_protocol_attributes(void)
{
    struct scmi_protocol_attributes_p2a ret_payload = {
        .status = SCMI_SUCCESS,
        .attributes = FAKE_POWER_CAPPING_IDX_COUNT,
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND_NO_PAYLOAD(MOD_SCMI_PROTOCOL_ATTRIBUTES);
}

void utest_message_handler_protocol_msg_attributes_unsupported_msgs(void)
{
    struct scmi_protocol_message_attributes_a2p cmd_payload = {
        .message_id = MOD_SCMI_POWER_CAPPING_COMMAND_COUNT
    };
    struct scmi_protocol_message_attributes_p2a ret_payload = {
        .status = SCMI_NOT_FOUND
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_NOT_FOUND);
    /* Test unsupported messages */
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_PROTOCOL_MESSAGE_ATTRIBUTES, cmd_payload);
}

void utest_message_handler_protocol_msg_attributes_maxlimits(void)
{
    struct scmi_protocol_message_attributes_a2p cmd_payload = {
        .message_id = UINT32_MAX
    };
    struct scmi_protocol_message_attributes_p2a ret_payload = {
        .status = SCMI_NOT_FOUND
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_NOT_FOUND);
    /* Test unsupported messages */
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_PROTOCOL_MESSAGE_ATTRIBUTES, cmd_payload);
}

void utest_message_handler_protocol_msg_attributes_supported_msgs(void)
{
    uint32_t message_id;
    struct scmi_protocol_message_attributes_a2p cmd_payload;
    struct scmi_protocol_message_attributes_p2a ret_payload = {
        .status = SCMI_SUCCESS
    };
    /* Test all supported messages */

    for (message_id = 0; message_id < MOD_SCMI_POWER_CAPPING_CAP_SET;
         message_id++) {
        cmd_payload.message_id = message_id;

        mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
            SCMI_SUCCESS);
#ifdef BUILD_HAS_MOD_RESOURCE_PERMS
        RESOURCE_PERMISSION_RESOURCE_PASS_TEST();
#endif
        EXPECT_RESPONSE_SUCCESS(ret_payload);
        TEST_SCMI_COMMAND(MOD_SCMI_PROTOCOL_MESSAGE_ATTRIBUTES, cmd_payload);
    }
}

void utest_message_handler_domain_invalid(void)
{
    struct scmi_power_capping_domain_attributes_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_COUNT
    };

    struct scmi_power_capping_domain_attributes_p2a ret_payload = {
        .status = SCMI_NOT_FOUND,
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_NOT_FOUND);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_DOMAIN_ATTRIBUTES, cmd_payload);
}

void utest_message_handler_domain_attributes_valid(void)
{
    uint32_t min_pai = MIN_DEFAULT_PAI;
    uint32_t max_pai = MAX_DEFAULT_PAI;
    uint32_t pai_step = 1;

    struct mod_scmi_power_capping_domain_context *domain_ctx =
        &domain_ctx_table[FAKE_POWER_CAPPING_IDX_1];
    const struct mod_scmi_power_capping_domain_config *config =
        domain_ctx->config;

    struct scmi_power_capping_domain_attributes_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1
    };

    domain_ctx->cap_config_support = true;

    struct scmi_power_capping_domain_attributes_p2a ret_payload = {
        .status = SCMI_SUCCESS,
        .attributes = 1u << POWER_CAP_CONF_SUP_POS | 1u << PAI_CONF_SUP_POS |
            config->power_cap_unit << POWER_UNIT_POS,
        .name = "TestPowerCap",
        .min_pai = min_pai,
        .max_pai = max_pai,
        .pai_step = pai_step,
        .min_power_cap = config->min_power_cap,
        .max_power_cap = config->max_power_cap,
        .power_cap_step = config->power_cap_step,
        .max_sustainable_power = config->max_sustainable_power,
        .parent_id = config->parent_idx,
    };

    uint32_t expected_pai_step = pai_step;
    uint32_t expected_min_pai = min_pai;
    uint32_t expected_max_pai = max_pai;

    get_averaging_interval_step_ExpectAndReturn(
        config->power_capping_domain_id, NULL, FWK_SUCCESS);
    get_averaging_interval_step_IgnoreArg_pai_step();
    get_averaging_interval_step_ReturnThruPtr_pai_step(&expected_pai_step);

    get_averaging_interval_range_ExpectAndReturn(
        config->power_capping_domain_id, NULL, NULL, FWK_SUCCESS);
    get_averaging_interval_range_IgnoreArg_min_pai();
    get_averaging_interval_range_IgnoreArg_max_pai();
    get_averaging_interval_range_ReturnThruPtr_min_pai(&expected_min_pai);
    get_averaging_interval_range_ReturnThruPtr_max_pai(&expected_max_pai);

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    ret_payload.attributes |= config->cap_pai_change_notification_support
        << POWER_CAPPING_NOTIF_SUP_POS;
    ret_payload.attributes |=
        config->power_measurements_change_notification_support
        << POWER_MEAS_NOTIF_SUP_POS;
#endif

    fwk_module_get_element_name_ExpectAndReturn(
        FWK_ID_ELEMENT(
            FWK_MODULE_IDX_SCMI_POWER_CAPPING, cmd_payload.domain_id),
        (char *)ret_payload.name);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_DOMAIN_ATTRIBUTES, cmd_payload);
}

void utest_message_handler_power_capping_get_valid(void)
{
    uint32_t cap = __LINE__; /* Arbitrary value */

    struct scmi_power_capping_cap_get_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1
    };

    struct scmi_power_capping_cap_get_p2a ret_payload = {
        .status = SCMI_SUCCESS,
        .power_cap = cap,
    };

    get_applied_cap_ExpectWithArrayAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        &cap,
        sizeof(cap),
        FWK_SUCCESS);
    get_applied_cap_IgnoreArg_cap();
    get_applied_cap_ReturnMemThruPtr_cap(&cap, sizeof(cap));

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_GET, cmd_payload);
}

void utest_message_handler_power_capping_get_failure(void)
{
    uint32_t cap = __LINE__; /* Arbitrary value */

    struct scmi_power_capping_cap_get_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1
    };

    struct scmi_power_capping_cap_get_p2a ret_payload = {
        .status = SCMI_GENERIC_ERROR,
    };

    get_applied_cap_ExpectWithArrayAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        &cap,
        sizeof(cap),
        FWK_E_DEVICE);
    get_applied_cap_IgnoreArg_cap();

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_GET, cmd_payload);
}

void utest_message_handler_power_capping_set_invalid_flags(void)
{
    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .flags = ~(ASYNC_FLAG(1) | IGN_DEL_RESP_FLAG(1)),
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_INVALID_PARAMETERS,
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_INVALID_PARAMETERS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_config_not_supported(void)
{
    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .flags = ASYNC_FLAG(1) | IGN_DEL_RESP_FLAG(1),
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_NOT_SUPPORTED,
    };

    domain_ctx_table[FAKE_POWER_CAPPING_IDX_1].config =
        &scmi_power_capping_config_1;

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_NOT_SUPPORTED);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_async_del_not_supported(void)
{
    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_2,
        .flags = (ASYNC_FLAG(1) | IGN_DEL_RESP_FLAG(0)),
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_NOT_SUPPORTED,
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_NOT_SUPPORTED);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_domain_busy(void)
{
    uint32_t cap = MIN_DEFAULT_POWER_CAP;
    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .power_cap = cap,
        .flags = ASYNC_FLAG(0),
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_BUSY,
    };

    test_set_domain_cap_pending_service_id(cmd_payload.domain_id, service_id_1);

    test_request_cap_config_supported(cmd_payload.domain_id, true);

    fwk_id_is_equal_ExpectAndReturn(service_id_1, FWK_ID_NONE, false);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_less_than_min_cap(void)
{
    uint32_t cap = MIN_DEFAULT_POWER_CAP - 1u;
    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .power_cap = cap,
        .flags = ASYNC_FLAG(0),
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_OUT_OF_RANGE,
    };

    test_request_cap_config_supported(cmd_payload.domain_id, true);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_more_than_max_cap(void)
{
    uint32_t cap = MAX_DEFAULT_POWER_CAP + 1u;
    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .power_cap = cap,
        .flags = ASYNC_FLAG(0),
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_OUT_OF_RANGE,
    };

    test_request_cap_config_supported(cmd_payload.domain_id, true);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_success_pending(void)
{
    uint32_t cap = MAX_DEFAULT_POWER_CAP;
    int status;

    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .power_cap = cap,
        .flags = ASYNC_FLAG(0),
    };

    test_request_cap_config_supported(cmd_payload.domain_id, true);

    request_cap_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        cmd_payload.power_cap,
        FWK_PENDING);

    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);
#endif

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);

    status = scmi_power_capping_message_handler(
        dummy_protocol_id,
        service_id_1,
        (void *)&cmd_payload,
        sizeof(cmd_payload),
        MOD_SCMI_POWER_CAPPING_CAP_SET);

    TEST_ASSERT_EQUAL_UINT32(status, FWK_SUCCESS);
    TEST_ASSERT_EQUAL_UINT32(
        domain_ctx_table[cmd_payload.domain_id].cap_pending_service_id.value,
        service_id_1.value);
}

void utest_message_handler_power_capping_set_success_sync(void)
{
    uint32_t cap = MIN_DEFAULT_POWER_CAP;
    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .power_cap = cap,
        .flags = ASYNC_FLAG(0),
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_SUCCESS,
    };

    test_request_cap_config_supported(cmd_payload.domain_id, true);

    request_cap_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        cmd_payload.power_cap,
        FWK_SUCCESS);

    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);
#endif

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_success_sync_uncap(void)
{
    uint32_t cap = DISABLE_CAP_VALUE;
    struct scmi_power_capping_cap_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .power_cap = cap,
        .flags = ASYNC_FLAG(0),
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_SUCCESS,
    };

    test_request_cap_config_supported(cmd_payload.domain_id, true);

    request_cap_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        cmd_payload.power_cap,
        FWK_SUCCESS);

    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);
#endif

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_SET, cmd_payload);
}

void utest_message_handler_power_capping_get_pai_valid(void)
{
    uint32_t pai = __LINE__; /* Arbitrary value */

    struct scmi_power_capping_pai_get_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1
    };

    struct scmi_power_capping_pai_get_p2a ret_payload = {
        .status = SCMI_SUCCESS,
        .pai = pai,
    };

    get_averaging_interval_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        NULL,
        FWK_SUCCESS);
    get_averaging_interval_IgnoreArg_pai();
    get_averaging_interval_ReturnThruPtr_pai(&pai);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_PAI_GET, cmd_payload);
}

void utest_message_handler_power_capping_get_pai_failure(void)
{
    struct scmi_power_capping_pai_get_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1
    };

    struct scmi_power_capping_pai_get_p2a ret_payload = {
        .status = SCMI_GENERIC_ERROR,
    };

    get_averaging_interval_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        NULL,
        FWK_E_DEVICE);
    get_averaging_interval_IgnoreArg_pai();

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_PAI_GET, cmd_payload);
}

void utest_message_handler_power_capping_set_pai_valid(void)
{
    uint32_t pai = MIN_DEFAULT_PAI;

    struct scmi_power_capping_pai_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .pai = pai,
    };

    struct scmi_power_capping_pai_set_p2a ret_payload = {
        .status = SCMI_SUCCESS,
    };

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);
#endif

    set_averaging_interval_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        pai,
        FWK_SUCCESS);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_PAI_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_pai_failure(void)
{
    uint32_t pai = MAX_DEFAULT_PAI;

    struct scmi_power_capping_pai_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .pai = pai,
    };

    struct scmi_power_capping_pai_set_p2a ret_payload = {
        .status = SCMI_GENERIC_ERROR,
    };

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);
#endif

    set_averaging_interval_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        pai,
        FWK_E_DEVICE);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_PAI_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_less_than_min_pai(void)
{
    uint32_t pai = MIN_DEFAULT_PAI - 1u;
    struct scmi_power_capping_pai_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .pai = pai,
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_OUT_OF_RANGE,
    };

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);
#endif

    set_averaging_interval_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        pai,
        FWK_E_RANGE);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_PAI_SET, cmd_payload);
}

void utest_message_handler_power_capping_set_more_than_max_pai(void)
{
    uint32_t pai = MAX_DEFAULT_PAI + 1u;
    struct scmi_power_capping_pai_set_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .pai = pai,
    };

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_OUT_OF_RANGE,
    };

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    fwk_id_is_equal_ExpectAndReturn(FWK_ID_NONE, FWK_ID_NONE, true);
#endif

    set_averaging_interval_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        pai,
        FWK_E_RANGE);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_PAI_SET, cmd_payload);
}

void utest_message_handler_power_capping_get_power_measurement_valid(void)
{
    uint32_t power = __LINE__; /* Arbitrary value */
    uint32_t pai = __LINE__; /* Arbitrary value */

    struct scmi_power_capping_measurements_get_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1
    };

    struct scmi_power_capping_measurements_get_p2a ret_payload = {
        .status = SCMI_SUCCESS,
        .power = power,
        .pai = pai,
    };

    get_average_power_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        NULL,
        FWK_SUCCESS);
    get_average_power_IgnoreArg_power();
    get_average_power_ReturnThruPtr_power(&power);

    get_averaging_interval_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        NULL,
        FWK_SUCCESS);
    get_averaging_interval_IgnoreArg_pai();
    get_averaging_interval_ReturnThruPtr_pai(&pai);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_MEASUREMENTS_GET, cmd_payload);
}

void utest_message_handler_power_capping_get_power_measurement_failure(void)
{
    struct scmi_power_capping_measurements_get_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
    };

    struct scmi_power_capping_measurements_get_p2a ret_payload = {
        .status = SCMI_GENERIC_ERROR,
    };

    get_average_power_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        NULL,
        FWK_E_DEVICE);
    get_average_power_IgnoreArg_power();

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_MEASUREMENTS_GET, cmd_payload);
}

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
void utest_message_handler_power_capping_cap_notify_valid_enable(void)
{
    struct scmi_power_capping_cap_notify_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .notify_enable = POWER_CAP_NOTIFY_ENABLE,
    };

    struct scmi_power_capping_cap_notify_p2a ret_payload = {
        .status = SCMI_SUCCESS,
    };

    scmi_notification_add_subscriber_ExpectAndReturn(
        MOD_SCMI_PROTOCOL_ID_POWER_CAPPING,
        FAKE_POWER_CAPPING_IDX_1,
        MOD_SCMI_POWER_CAPPING_CAP_NOTIFY,
        service_id_1,
        FWK_SUCCESS);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_NOTIFY, cmd_payload);
}

void utest_message_handler_power_capping_cap_notify_valid_disable(void)
{
    unsigned int agent_id;

    struct scmi_power_capping_cap_notify_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .notify_enable = POWER_CAP_NOTIFY_DISABLE,
    };

    struct scmi_power_capping_cap_notify_p2a ret_payload = {
        .status = SCMI_SUCCESS,
    };

    get_agent_id_ExpectAndReturn(service_id_1, NULL, FWK_SUCCESS);
    get_agent_id_IgnoreArg_agent_id();
    get_agent_id_ReturnMemThruPtr_agent_id(&agent_id, sizeof(agent_id));

    scmi_notification_remove_subscriber_ExpectAndReturn(
        MOD_SCMI_PROTOCOL_ID_POWER_CAPPING,
        agent_id,
        cmd_payload.domain_id,
        MOD_SCMI_POWER_CAPPING_CAP_NOTIFY,
        FWK_SUCCESS);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_CAP_NOTIFY, cmd_payload);
}

void utest_message_handler_power_capping_measurements_notify_valid_enable(void)
{
    struct scmi_power_capping_measurements_notify_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .notify_enable = MEASUREMENTS_NOTIFY_ENABLE,
    };

    struct scmi_power_capping_measurements_notify_p2a ret_payload = {
        .status = SCMI_SUCCESS,
    };

    scmi_notification_add_subscriber_ExpectAndReturn(
        MOD_SCMI_PROTOCOL_ID_POWER_CAPPING,
        FAKE_POWER_CAPPING_IDX_1,
        MOD_SCMI_POWER_CAPPING_MEASUREMENTS_NOTIFY,
        service_id_1,
        FWK_SUCCESS);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_MEASUREMENTS_NOTIFY, cmd_payload);
}

void utest_message_handler_power_capping_measurements_notify_valid_disable(void)
{
    unsigned int agent_id;

    struct scmi_power_capping_measurements_notify_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .notify_enable = MEASUREMENTS_NOTIFY_DISABLE,
    };

    struct scmi_power_capping_measurements_notify_p2a ret_payload = {
        .status = SCMI_SUCCESS,
    };

    get_agent_id_ExpectAndReturn(service_id_1, NULL, FWK_SUCCESS);
    get_agent_id_IgnoreArg_agent_id();
    get_agent_id_ReturnMemThruPtr_agent_id(&agent_id, sizeof(agent_id));

    scmi_notification_remove_subscriber_ExpectAndReturn(
        MOD_SCMI_PROTOCOL_ID_POWER_CAPPING,
        agent_id,
        cmd_payload.domain_id,
        MOD_SCMI_POWER_CAPPING_MEASUREMENTS_NOTIFY,
        FWK_SUCCESS);

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_SUCCESS);
    EXPECT_RESPONSE_SUCCESS(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_MEASUREMENTS_NOTIFY, cmd_payload);
}

void utest_pcapping_protocol_process_cap_pai_notify_event_success(void)
{
    unsigned int agent_id = __LINE__;
    uint32_t cap = __LINE__;
    uint32_t pai = __LINE__;
    int status = FWK_SUCCESS;
    struct fwk_event cap_pai_notify_event;

    struct pcapping_protocol_event_parameters event_params = {
        .domain_idx = FAKE_POWER_CAPPING_IDX_1,
        .service_id = service_id_1,
    };

    struct scmi_power_capping_cap_changed_p2a payload = {
        .agent_id = agent_id,
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .cap = cap,
        .pai = pai,
    };

    struct pcapping_protocol_event_parameters *event_params_ptr =
        (struct pcapping_protocol_event_parameters *)
            cap_pai_notify_event.params;

    *event_params_ptr = event_params;

    fwk_id_is_equal_ExpectAndReturn(service_id_1, FWK_ID_NONE, false);
    get_agent_id_ExpectAndReturn(service_id_1, NULL, FWK_SUCCESS);
    get_agent_id_IgnoreArg_agent_id();
    get_agent_id_ReturnMemThruPtr_agent_id(&agent_id, sizeof(agent_id));

    get_applied_cap_ExpectWithArrayAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        &cap,
        sizeof(cap),
        FWK_SUCCESS);
    get_applied_cap_IgnoreArg_cap();
    get_applied_cap_ReturnMemThruPtr_cap(&cap, sizeof(cap));

    get_averaging_interval_ExpectWithArrayAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        &pai,
        sizeof(pai),
        FWK_SUCCESS);
    get_averaging_interval_IgnoreArg_pai();
    get_averaging_interval_ReturnThruPtr_pai(&pai);

    scmi_notification_notify_ExpectWithArrayAndReturn(
        MOD_SCMI_PROTOCOL_ID_POWER_CAPPING,
        MOD_SCMI_POWER_CAPPING_CAP_NOTIFY,
        SCMI_POWER_CAPPING_CAP_CHANGED,
        &payload,
        sizeof(payload),
        sizeof(payload),
        FWK_SUCCESS);

    status =
        pcapping_protocol_process_cap_pai_notify_event(&cap_pai_notify_event);

    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
}

void utest_pcapping_protocol_process_measurements_notify_event_success(void)
{
    uint32_t power = __LINE__;
    int status = FWK_SUCCESS;
    struct fwk_event measurements_notify_event;

    struct pcapping_protocol_event_parameters event_params = {
        .domain_idx = FAKE_POWER_CAPPING_IDX_1,
        .service_id = service_id_1,
    };

    struct scmi_power_capping_measurements_changed_p2a payload = {
        .agent_id = SCMI_POWER_CAPPING_AGENT_ID_PLATFORM,
        .domain_id = FAKE_POWER_CAPPING_IDX_1,
        .power = power,
    };

    struct pcapping_protocol_event_parameters *event_params_ptr =
        (struct pcapping_protocol_event_parameters *)
            measurements_notify_event.params;

    *event_params_ptr = event_params;

    get_average_power_ExpectAndReturn(
        scmi_power_capping_default_config.power_capping_domain_id,
        NULL,
        FWK_SUCCESS);
    get_average_power_IgnoreArg_power();
    get_average_power_ReturnThruPtr_power(&power);

    scmi_notification_notify_ExpectWithArrayAndReturn(
        MOD_SCMI_PROTOCOL_ID_POWER_CAPPING,
        MOD_SCMI_POWER_CAPPING_MEASUREMENTS_NOTIFY,
        SCMI_POWER_CAPPING_MEASUREMENTS_CHANGED,
        &payload,
        sizeof(payload),
        sizeof(payload),
        FWK_SUCCESS);

    status = pcapping_protocol_process_measurements_notify_event(
        &measurements_notify_event);

    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
}

#endif

#ifdef BUILD_HAS_MOD_RESOURCE_PERMS
void utest_message_handler_invalid_agent_id(void)
{
    struct scmi_power_capping_domain_attributes_a2p cmd_payload = {
        .domain_id = FAKE_POWER_CAPPING_IDX_1
    };

    struct scmi_power_capping_domain_attributes_p2a ret_payload = {
        .status = SCMI_DENIED
    };

    mod_scmi_from_protocol_api_scmi_frame_validation_ExpectAnyArgsAndReturn(
        SCMI_DENIED);
    EXPECT_RESPONSE_ERROR(ret_payload);
    TEST_SCMI_COMMAND(MOD_SCMI_POWER_CAPPING_DOMAIN_ATTRIBUTES, cmd_payload);
}

void utest_message_handler_invalid_resource_permissions(void)
{
    uint32_t message_id;
    /*
     * As the domain id is the first element of the payload and it is the only
     * necessary data in this test , we will use a u32t to represent the
     * payload and the domain id.
     */
    uint32_t domain_id = FAKE_POWER_CAPPING_IDX_COUNT;
    uint32_t agent_id = __LINE__;

    for (message_id = MOD_SCMI_PROTOCOL_VERSION;
         message_id <= MOD_SCMI_POWER_CAPPING_CAP_SET;
         message_id++) {
        get_agent_id_ExpectAndReturn(service_id_1, NULL, FWK_SUCCESS);
        get_agent_id_IgnoreArg_agent_id();
        get_agent_id_ReturnThruPtr_agent_id(&agent_id);

        agent_has_resource_permission_ExpectAndReturn(
            agent_id,
            MOD_SCMI_PROTOCOL_ID_POWER_CAPPING,
            message_id,
            domain_id,
            MOD_RES_PERMS_ACCESS_DENIED);

        status = scmi_power_capping_permissions_handler(
            message_id, service_id_1, &domain_id);
        TEST_ASSERT_EQUAL(status, FWK_E_ACCESS);
    }
}

#endif

void utest_pcapping_protocol_init(void)
{
    int domain_count = __LINE__;
    struct mod_scmi_power_capping_context ctx;
    struct mod_scmi_power_capping_domain_context *fake_table_pointer =
        (struct mod_scmi_power_capping_domain_context *)__LINE__;

    ctx.domain_count = domain_count;
    ctx.power_capping_domain_ctx_table = fake_table_pointer;
    pcapping_protocol_init(&ctx);
    TEST_ASSERT_EQUAL(
        pcapping_protocol_ctx.power_capping_domain_count, domain_count);
    TEST_ASSERT_EQUAL(
        pcapping_protocol_ctx.power_capping_domain_ctx_table,
        fake_table_pointer);
}

void utest_pcapping_protocol_domain_init_success(void)
{
    int status;

    status = pcapping_protocol_domain_init(
        FAKE_POWER_CAPPING_IDX_2, &scmi_power_capping_config_1);
    TEST_ASSERT_EQUAL_PTR(
        domain_ctx_table[FAKE_POWER_CAPPING_IDX_2].config,
        &scmi_power_capping_config_1);
    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
}

void utest_pcapping_protocol_domain_init_failure(void)
{
    int status;
    int domain_idx = __LINE__;
    pcapping_protocol_ctx.power_capping_domain_count = domain_idx;

    status =
        pcapping_protocol_domain_init(domain_idx, &scmi_power_capping_config_1);
    TEST_ASSERT_EQUAL(status, FWK_E_PARAM);
}

void utest_pcapping_protocol_bind_scmi_failure(void)
{
    int status;

    fwk_module_bind_ExpectAndReturn(
        FWK_ID_MODULE(FWK_MODULE_IDX_SCMI),
        FWK_ID_API(FWK_MODULE_IDX_SCMI, MOD_SCMI_API_IDX_PROTOCOL),
        &(pcapping_protocol_ctx.scmi_api),
        FWK_E_DEVICE);

    status = pcapping_protocol_bind();
    TEST_ASSERT_EQUAL(status, FWK_E_DEVICE);
}

void utest_pcapping_protocol_bind(void)
{
    int status;

    fwk_module_bind_ExpectAndReturn(
        FWK_ID_MODULE(FWK_MODULE_IDX_SCMI),
        FWK_ID_API(FWK_MODULE_IDX_SCMI, MOD_SCMI_API_IDX_PROTOCOL),
        &(pcapping_protocol_ctx.scmi_api),
        FWK_SUCCESS);

#ifdef BUILD_HAS_MOD_RESOURCE_PERMS
    fwk_module_bind_ExpectAndReturn(
        FWK_ID_MODULE(FWK_MODULE_IDX_RESOURCE_PERMS),
        FWK_ID_API(FWK_MODULE_IDX_RESOURCE_PERMS, MOD_RES_PERM_RESOURCE_PERMS),
        &(pcapping_protocol_ctx.res_perms_api),
        FWK_SUCCESS);
#endif

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    fwk_module_bind_ExpectAndReturn(
        FWK_ID_MODULE(FWK_MODULE_IDX_SCMI),
        FWK_ID_API(FWK_MODULE_IDX_SCMI, MOD_SCMI_API_IDX_NOTIFICATION),
        &(pcapping_protocol_ctx.scmi_notification_api),
        FWK_SUCCESS);
#endif
    status = pcapping_protocol_bind();
    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
}

void utest_pcapping_protocol_start_module(void)
{
    int status;
    fwk_id_t module_id = FWK_ID_MODULE_INIT(FWK_MODULE_IDX_SCMI_POWER_CAPPING);

    fwk_id_is_type_ExpectAndReturn(module_id, FWK_ID_TYPE_MODULE, true);

    status = pcapping_protocol_start(module_id);
    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
}

void utest_pcapping_protocol_start_element(void)
{
    int status;
    const unsigned int element_idx = FAKE_POWER_CAPPING_IDX_2;
    fwk_id_t element_id =
        FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_SCMI_POWER_CAPPING, element_idx);

    fwk_id_get_element_idx_ExpectAndReturn(element_id, element_idx);

    fwk_id_is_type_ExpectAndReturn(element_id, FWK_ID_TYPE_MODULE, false);

    fwk_notification_subscribe_ExpectAndReturn(
        FWK_ID_NOTIFICATION(
            FWK_MODULE_IDX_POWER_CAPPING,
            MOD_POWER_CAPPING_NOTIFICATION_IDX_CAP_CHANGE),
        domain_ctx_table[element_idx].config->power_capping_domain_id,
        element_id,
        FWK_SUCCESS);

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    unsigned int agent_count = __LINE__;

    fwk_notification_subscribe_ExpectAndReturn(
        FWK_ID_NOTIFICATION(
            FWK_MODULE_IDX_POWER_CAPPING,
            MOD_POWER_CAPPING_NOTIFICATION_IDX_PAI_CHANGED),
        FWK_ID_MODULE(FWK_MODULE_IDX_POWER_CAPPING),
        element_id,
        FWK_SUCCESS);

    fwk_notification_subscribe_ExpectAndReturn(
        FWK_ID_NOTIFICATION(
            FWK_MODULE_IDX_POWER_CAPPING,
            MOD_POWER_CAPPING_NOTIFICATION_IDX_MEASUREMENTS_CHANGED),
        FWK_ID_MODULE(FWK_MODULE_IDX_POWER_CAPPING),
        element_id,
        FWK_SUCCESS);

    get_agent_count_ExpectAnyArgsAndReturn(FWK_SUCCESS);
    get_agent_count_ReturnMemThruPtr_agent_count(
        &agent_count, sizeof(agent_count));

    scmi_notification_init_ExpectAndReturn(
        MOD_SCMI_PROTOCOL_ID_POWER_CAPPING,
        agent_count,
        FAKE_POWER_CAPPING_IDX_COUNT,
        MOD_SCMI_POWER_CAPPING_NOTIFICATION_COUNT,
        FWK_SUCCESS);
#endif
    status = pcapping_protocol_start(element_id);
    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
}

void utest_pcapping_protocol_process_notification(void)
{
    int status;
    const unsigned int element_idx = 0u;

    struct fwk_event notification_event = {
        .id = pcapping_protocol_cap_notification,
        .target_id =
            FWK_ID_ELEMENT_INIT(FWK_MODULE_IDX_SCMI_POWER_CAPPING, element_idx),
    };

    domain_ctx_table[element_idx].cap_pending_service_id = service_id_1;

    struct scmi_power_capping_cap_set_p2a ret_payload = {
        .status = SCMI_SUCCESS,
    };

    fwk_id_get_element_idx_ExpectAndReturn(
        notification_event.target_id, element_idx);

    fwk_id_is_equal_ExpectAndReturn(
        notification_event.id, pcapping_protocol_cap_notification, true);

#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    __fwk_put_event_ExpectAnyArgsAndReturn(FWK_SUCCESS);
#endif

    fwk_id_is_equal_ExpectAndReturn(service_id_1, FWK_ID_NONE, false);

    EXPECT_RESPONSE_SUCCESS(ret_payload);

    status = pcapping_protocol_process_fwk_notification(&notification_event);

    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
    TEST_ASSERT_EQUAL(
        domain_ctx_table[element_idx].cap_pending_service_id.value,
        FWK_ID_NONE.value);
}

void utest_pcapping_protocol_process_bind_request_success(void)
{
    int status;
    const void *api;
    fwk_id_t api_id = FWK_ID_API(
        FWK_MODULE_IDX_SCMI_POWER_CAPPING,
        MOD_SCMI_POWER_CAPPING_API_IDX_REQUEST);

    fwk_id_is_equal_ExpectAndReturn(api_id, api_id, true);

    status = pcapping_protocol_process_bind_request(api_id, &api);
    TEST_ASSERT_EQUAL_PTR(&scmi_power_capping_mod_scmi_to_protocol_api, api);
    TEST_ASSERT_EQUAL(status, FWK_SUCCESS);
}

void utest_pcapping_protocol_process_bind_request_failure(void)
{
    int status;
    const void *api;
    fwk_id_t api_id_invalid;
    fwk_id_t api_id_valid = FWK_ID_API(
        FWK_MODULE_IDX_SCMI_POWER_CAPPING,
        MOD_SCMI_POWER_CAPPING_API_IDX_REQUEST);

    fwk_id_is_equal_ExpectAndReturn(api_id_invalid, api_id_valid, false);

    status = pcapping_protocol_process_bind_request(api_id_invalid, &api);
    TEST_ASSERT_EQUAL(status, FWK_E_SUPPORT);
}

int scmi_power_capping_protocol_test_main(void)
{
    test_init();
    RUN_TEST(utest_get_scmi_protocol_id);
    RUN_TEST(utest_message_handler_cmd_error);
    RUN_TEST(utest_message_handler_invalid_cmd);
    RUN_TEST(utest_message_handler_protocol_version);
    RUN_TEST(utest_message_handler_protocol_attributes);
    RUN_TEST(utest_message_handler_protocol_msg_attributes_unsupported_msgs);
    RUN_TEST(utest_message_handler_protocol_msg_attributes_maxlimits);
    RUN_TEST(utest_message_handler_protocol_msg_attributes_supported_msgs);
    RUN_TEST(utest_message_handler_domain_invalid);
    RUN_TEST(utest_message_handler_domain_attributes_valid);
    RUN_TEST(utest_message_handler_power_capping_get_valid);
    RUN_TEST(utest_message_handler_power_capping_get_failure);
    RUN_TEST(utest_message_handler_power_capping_set_invalid_flags);
    RUN_TEST(utest_message_handler_power_capping_set_config_not_supported);
    RUN_TEST(utest_message_handler_power_capping_set_async_del_not_supported);
    RUN_TEST(utest_message_handler_power_capping_set_domain_busy);
    RUN_TEST(utest_message_handler_power_capping_set_less_than_min_cap);
    RUN_TEST(utest_message_handler_power_capping_set_more_than_max_cap);
    RUN_TEST(utest_message_handler_power_capping_set_success_pending);
    RUN_TEST(utest_message_handler_power_capping_set_success_sync);
    RUN_TEST(utest_message_handler_power_capping_set_success_sync_uncap);
    RUN_TEST(utest_message_handler_power_capping_get_pai_valid);
    RUN_TEST(utest_message_handler_power_capping_get_pai_failure);
    RUN_TEST(utest_message_handler_power_capping_set_pai_valid);
    RUN_TEST(utest_message_handler_power_capping_set_pai_failure);
    RUN_TEST(utest_message_handler_power_capping_set_less_than_min_pai);
    RUN_TEST(utest_message_handler_power_capping_set_more_than_max_pai);
    RUN_TEST(utest_message_handler_power_capping_get_power_measurement_valid);
    RUN_TEST(utest_message_handler_power_capping_get_power_measurement_failure);
#ifdef BUILD_HAS_SCMI_NOTIFICATIONS
    RUN_TEST(utest_message_handler_power_capping_cap_notify_valid_enable);
    RUN_TEST(utest_message_handler_power_capping_cap_notify_valid_disable);
    RUN_TEST(
        utest_message_handler_power_capping_measurements_notify_valid_enable);
    RUN_TEST(
        utest_message_handler_power_capping_measurements_notify_valid_disable);
    RUN_TEST(utest_pcapping_protocol_process_cap_pai_notify_event_success);
    RUN_TEST(utest_pcapping_protocol_process_measurements_notify_event_success);
#endif
    RUN_TEST(utest_message_handler_un_implemented_message);
#ifdef BUILD_HAS_MOD_RESOURCE_PERMS
    RUN_TEST(utest_message_handler_invalid_agent_id);
    RUN_TEST(utest_message_handler_invalid_resource_permissions);
#endif
    RUN_TEST(utest_pcapping_protocol_init);
    RUN_TEST(utest_pcapping_protocol_domain_init_success);
    RUN_TEST(utest_pcapping_protocol_domain_init_failure);
    RUN_TEST(utest_pcapping_protocol_bind_scmi_failure);
    RUN_TEST(utest_pcapping_protocol_bind);
    RUN_TEST(utest_pcapping_protocol_start_module);
    RUN_TEST(utest_pcapping_protocol_start_element);
    RUN_TEST(utest_pcapping_protocol_process_notification);
    RUN_TEST(utest_pcapping_protocol_process_bind_request_success);
    RUN_TEST(utest_pcapping_protocol_process_bind_request_failure);
    return UNITY_END();
}

#if !defined(TEST_ON_TARGET)
int main(void)
{
    return scmi_power_capping_protocol_test_main();
}
#endif
