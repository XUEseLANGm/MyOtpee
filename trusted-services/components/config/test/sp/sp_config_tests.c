/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <service/test_runner/provider/backend/simple_c/simple_c_test_runner.h>
#include <config/interface/config_store.h>
#include <config/interface/config_blob.h>
#include <platform/interface/device_region.h>
#include <stdint.h>

/**
 * Secure Partition configuration tests for checking configuartion
 * data passed to an SP at initialisation.  These tests rely on
 * the SP manifest for deployments/env_test.
 */

/*
 * Check that the loaded configuration includes one or more
 * device regions.
 */
static bool check_device_region_loaded(struct test_failure *failure)
{
	return config_store_count(CONFIG_CLASSIFIER_DEVICE_REGION) > 0;
}

/*
 * Check that a device region for a 'trng' device has been loaded
 * and that values are as expected.
 */
static bool check_trng_device_region_loaded(struct test_failure *failure)
{
	struct device_region dev_region;

	bool passed = config_store_query(CONFIG_CLASSIFIER_DEVICE_REGION,
		"trng", 0,
		&dev_region, sizeof(dev_region));

	if (passed) {

		passed = (dev_region.dev_instance == 0);
		failure->line_num = __LINE__;
		failure->info = dev_region.dev_instance;

		if (passed) {
			passed = (dev_region.io_region_size == 0x1000);
			failure->line_num = __LINE__;
			failure->info = dev_region.io_region_size;
		}
	}
	else {

		failure->line_num = __LINE__;
	}

	return passed;
}

/*
 * Check access to some trng registers
 */
static bool check_trng_register_access(struct test_failure *failure)
{
	struct device_region dev_region;

	bool passed = config_store_query(CONFIG_CLASSIFIER_DEVICE_REGION,
		"trng", 0,
		&dev_region, sizeof(dev_region));

	if (passed) {

		/* Expect reset values to be read from a selection of TRNG registers */
		uint32_t reg_val;

		/* PID4 */
		reg_val = *((volatile uint32_t*)((uint8_t*)dev_region.base_addr + 0xfd0));
		passed = (reg_val == 0x00000004);
		failure->line_num = __LINE__;
		failure->info = reg_val;

		/* PID0 */
		if (passed) {
			reg_val = *((volatile uint32_t*)((uint8_t*)dev_region.base_addr + 0xfe0));
			passed = (reg_val == 0x000000aa);
			failure->line_num = __LINE__;
			failure->info = reg_val;
		}
	}
	else {

		failure->line_num = __LINE__;
	}

	return passed;
}

/*
 * Check that the loaded configuration includes one or more
 * configuration blobs.  One is expected for teh TPM event log.
 */
static bool check_config_blob_loaded(struct test_failure *failure)
{
	return config_store_count(CONFIG_CLASSIFIER_BLOB) > 0;
}

/*
 * Check that the event log has been loaded.
 */
static bool check_event_log_loaded(struct test_failure *failure)
{
	struct config_blob config_blob;

	bool passed = config_store_query(CONFIG_CLASSIFIER_BLOB,
		"EVENT_LOG", 0,
		&config_blob, sizeof(config_blob));

	return passed;
}

/*
 * Check that the event log can be accessed
 */
static bool check_event_log_access(struct test_failure *failure)
{
	struct config_blob config_blob;

	bool passed = config_store_query(CONFIG_CLASSIFIER_BLOB,
		"EVENT_LOG", 0,
		&config_blob, sizeof(config_blob));

	if (passed) {

		passed = (config_blob.data_len > 0);
		failure->line_num = __LINE__;

		if (passed) {
			passed = (config_blob.data);
			failure->line_num = __LINE__;
		}
	}
	else {

		failure->line_num = __LINE__;
	}

	return passed;
}

/**
 * Define an register test group
 */
void sp_config_tests_register(void)
{
	static const struct simple_c_test_case sp_config_tests[] = {
		{.name = "DevRegionLoaded", .test_func = check_device_region_loaded},
		{.name = "TrngDevRegionLoaded", .test_func = check_trng_device_region_loaded},
		{.name = "TrngRegAccess", .test_func = check_trng_register_access},
		{.name = "ConfigBlobLoaded", .test_func = check_config_blob_loaded},
		{.name = "EventLogLoaded", .test_func = check_event_log_loaded},
		{.name = "EventLogAccess", .test_func = check_event_log_access}
	};

	static const struct simple_c_test_group sp_config_test_group =
	{
		.group = "SpConfigTests",
		.num_test_cases = sizeof(sp_config_tests)/sizeof(struct simple_c_test_case),
		.test_cases = sp_config_tests
	};

	simple_c_test_runner_register_group(&sp_config_test_group);
}
