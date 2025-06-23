/*
 * Arm SCP/MCP Software
 * Copyright (c) 2022-2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "scp_unity.h"
#include "unity.h"

#ifdef TEST_ON_TARGET
#    include <fwk_id.h>
#    include <fwk_module.h>
#else

#    include <Mockfwk_id.h>
#    include <Mockfwk_module.h>
#endif

#include <internal/transport.h>

#include <mod_transport.h>

#include <fwk_element.h>
#include <fwk_macros.h>

#include UNIT_TEST_SRC

#define BUILD_HAS_BASE_PROTOCOL

#define FAKE_MODULE_ID    0x5
#define TEST_MAILBOX_SIZE 100

enum fake_services {
    FAKE_SERVICE_IDX_PSCI,
    FAKE_SERVICE_IDX_OSPM,
    FAKE_SERVICE_IDX_COUNT,
};

void setUp(void)
{
    fwk_id_t service_id =
        FWK_ID_ELEMENT_INIT(FAKE_MODULE_ID, FAKE_SERVICE_IDX_OSPM);

    transport_init(service_id, FAKE_SERVICE_IDX_COUNT, NULL);

    fwk_id_get_element_idx_ExpectAndReturn(service_id, FAKE_SERVICE_IDX_OSPM);

    static const struct mod_transport_channel_config config = {
        .transport_type = MOD_TRANSPORT_CHANNEL_TRANSPORT_TYPE_IN_BAND,
        .channel_type = MOD_TRANSPORT_CHANNEL_TYPE_REQUESTER,
        .in_band_mailbox_size = TEST_MAILBOX_SIZE
    };
    transport_channel_init(service_id, 0, &config);
}

void tearDown(void)
{
}

void test_transport_payload_size(void)
{
    struct transport_channel_ctx *channel_ctx =
        &transport_ctx.channel_ctx_table[FAKE_SERVICE_IDX_OSPM];

    TEST_ASSERT_EQUAL(
        TEST_MAILBOX_SIZE - sizeof(struct mod_transport_buffer),
        channel_ctx->max_payload_size);
}

void test_transport_write_payload_invalid_param_null_payload(void)
{
    int status;

    fwk_id_t service_id =
        FWK_ID_ELEMENT_INIT(FAKE_MODULE_ID, FAKE_SERVICE_IDX_OSPM);
    char string[] = "Test";

    /* We are not going through a proper message cycle so let's set the lock */
    struct transport_channel_ctx *channel_ctx =
        &transport_ctx.channel_ctx_table[FAKE_SERVICE_IDX_OSPM];
    channel_ctx->locked = true;

    fwk_id_get_element_idx_ExpectAndReturn(service_id, FAKE_SERVICE_IDX_OSPM);

    status = transport_write_payload(service_id, 0, NULL, sizeof(string));
    TEST_ASSERT_EQUAL(FWK_E_PARAM, status);
}

void test_transport_write_payload_invalid_param_large_size(void)
{
    int status;
    size_t offset = 50;

    fwk_id_t service_id =
        FWK_ID_ELEMENT_INIT(FAKE_MODULE_ID, FAKE_SERVICE_IDX_OSPM);
    char payload[] = "Test";

    /* We are not going through a proper message cycle so let's set the lock */
    struct transport_channel_ctx *channel_ctx =
        &transport_ctx.channel_ctx_table[FAKE_SERVICE_IDX_OSPM];
    channel_ctx->locked = true;

    fwk_id_get_element_idx_ExpectAndReturn(service_id, FAKE_SERVICE_IDX_OSPM);

    status = transport_write_payload(
        service_id, offset, payload, SIZE_MAX - (offset / 2));
    TEST_ASSERT_EQUAL(FWK_E_PARAM, status);
}

void test_transport_write_payload_invalid_param_large_offset(void)
{
    int status;

    fwk_id_t service_id =
        FWK_ID_ELEMENT_INIT(FAKE_MODULE_ID, FAKE_SERVICE_IDX_OSPM);
    char payload[] = "Test";

    /* We are not going through a proper message cycle so let's set the lock */
    struct transport_channel_ctx *channel_ctx =
        &transport_ctx.channel_ctx_table[FAKE_SERVICE_IDX_OSPM];
    channel_ctx->locked = true;

    fwk_id_get_element_idx_ExpectAndReturn(service_id, FAKE_SERVICE_IDX_OSPM);

    status = transport_write_payload(
        service_id, SIZE_MAX - 2, payload, sizeof(payload));
    TEST_ASSERT_EQUAL(FWK_E_PARAM, status);
}

void test_transport_write_payload_invalid_param_offset_beyond_end(void)
{
    int status;

    fwk_id_t service_id =
        FWK_ID_ELEMENT_INIT(FAKE_MODULE_ID, FAKE_SERVICE_IDX_OSPM);
    char payload[] = "Test";

    /* We are not going through a proper message cycle so let's set the lock */
    struct transport_channel_ctx *channel_ctx =
        &transport_ctx.channel_ctx_table[FAKE_SERVICE_IDX_OSPM];
    channel_ctx->locked = true;

    fwk_id_get_element_idx_ExpectAndReturn(service_id, FAKE_SERVICE_IDX_OSPM);

    status = transport_write_payload(
        service_id, channel_ctx->max_payload_size, payload, 1);
    TEST_ASSERT_EQUAL(FWK_E_PARAM, status);
}

void test_transport_write_payload_valid_param_start(void)
{
    int status;

    fwk_id_t service_id =
        FWK_ID_ELEMENT_INIT(FAKE_MODULE_ID, FAKE_SERVICE_IDX_OSPM);
    char payload[] = "Test";

    /* We are not going through a proper message cycle so let's set the lock */
    struct transport_channel_ctx *channel_ctx =
        &transport_ctx.channel_ctx_table[FAKE_SERVICE_IDX_OSPM];
    channel_ctx->locked = true;

    fwk_id_get_element_idx_ExpectAndReturn(service_id, FAKE_SERVICE_IDX_OSPM);

    status = transport_write_payload(service_id, 0, payload, sizeof(payload));
    TEST_ASSERT_EQUAL(FWK_SUCCESS, status);

    uint8_t *dst_payload = (uint8_t *)channel_ctx->out->payload;
    for (size_t i = 0; i < sizeof(payload); i++) {
        TEST_ASSERT_EQUAL(payload[i], dst_payload[i]);
    }
}

void test_transport_write_payload_valid_param_end(void)
{
    int status;

    fwk_id_t service_id =
        FWK_ID_ELEMENT_INIT(FAKE_MODULE_ID, FAKE_SERVICE_IDX_OSPM);
    char payload[] = "T";

    /* We are not going through a proper message cycle so let's set the lock */
    struct transport_channel_ctx *channel_ctx =
        &transport_ctx.channel_ctx_table[FAKE_SERVICE_IDX_OSPM];
    channel_ctx->locked = true;

    fwk_id_get_element_idx_ExpectAndReturn(service_id, FAKE_SERVICE_IDX_OSPM);

    status = transport_write_payload(
        service_id, channel_ctx->max_payload_size - 1, payload, 1);
    TEST_ASSERT_EQUAL(FWK_SUCCESS, status);

    uint8_t *dst_payload = (uint8_t *)channel_ctx->out->payload;
    TEST_ASSERT_EQUAL(
        payload[0], dst_payload[channel_ctx->max_payload_size - 1]);
}

int scmi_test_main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_transport_payload_size);
    RUN_TEST(test_transport_write_payload_invalid_param_null_payload);
    RUN_TEST(test_transport_write_payload_invalid_param_large_size);
    RUN_TEST(test_transport_write_payload_invalid_param_large_offset);
    RUN_TEST(test_transport_write_payload_invalid_param_offset_beyond_end);
    RUN_TEST(test_transport_write_payload_valid_param_start);
    RUN_TEST(test_transport_write_payload_valid_param_end);

    return UNITY_END();
}

#if !defined(TEST_ON_TARGET)
int main(void)
{
    return scmi_test_main();
}
#endif
