/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstring>
#include <config/interface/config_store.h>
#include <config/ramstore/config_ramstore.h>
#include <config/interface/config_blob.h>
#include <platform/interface/device_region.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(ConfigRamstoreTests)
{
	void setup()
	{
		config_ramstore_init();
	}

	void teardown()
	{
		config_ramstore_deinit();
	}
};

TEST(ConfigRamstoreTests, checkEmptyConfig)
{
	struct config_blob blob;

	/* Expect queries to an empty store to return gracefully */
	bool query_result = config_store_query(CONFIG_CLASSIFIER_BLOB, "flash", 0,
		&blob, sizeof(blob));

	CHECK_FALSE(query_result);
	UNSIGNED_LONGS_EQUAL(0, config_store_count(CONFIG_CLASSIFIER_DEVICE_REGION));
	UNSIGNED_LONGS_EQUAL(0, config_store_count(CONFIG_CLASSIFIER_MEMORY_REGION));
	UNSIGNED_LONGS_EQUAL(0, config_store_count(CONFIG_CLASSIFIER_BLOB));
}

TEST(ConfigRamstoreTests, checkSingleConfig)
{
	struct device_region config;

	/* This would be external configuration, obtained say from device tree */
	strcpy(config.dev_class, "fs");
	config.dev_instance = 2;
	config.base_addr = (uintptr_t)0x0f000010;
	config.io_region_size = 0x100;

	/* Add the configuration object */
	bool success = config_store_add(CONFIG_CLASSIFIER_DEVICE_REGION,
		config.dev_class, config.dev_instance,
		&config, sizeof(config));

	CHECK_TRUE(success);

	/* Expect query find the config object */
	struct device_region query_result;
	 success = config_store_query(CONFIG_CLASSIFIER_DEVICE_REGION,
		config.dev_class, config.dev_instance,
		&query_result, sizeof(query_result));

	CHECK_TRUE(success);
	STRCMP_EQUAL(config.dev_class, query_result.dev_class);
	UNSIGNED_LONGS_EQUAL(config.dev_instance, query_result.dev_instance);
	UNSIGNED_LONGS_EQUAL(config.base_addr, query_result.base_addr);
	UNSIGNED_LONGS_EQUAL(config.io_region_size, query_result.io_region_size);
}

TEST(ConfigRamstoreTests, checkMultipleConfig)
{
	/* Add first config object */
	struct device_region config1;

	strcpy(config1.dev_class, "flash");
	config1.dev_instance = 0;
	config1.base_addr = (uintptr_t)0x0f000010;
	config1.io_region_size = 0x100;

	bool success = config_store_add(CONFIG_CLASSIFIER_DEVICE_REGION,
		config1.dev_class, config1.dev_instance,
		&config1, sizeof(config1));

	CHECK_TRUE(success);

	/* Add second config object */
	struct config_blob config2;

	uint8_t config2_data[100];
	config2.data = config2_data;
	config2.data_len = sizeof(config2_data);

	success = config_store_add(CONFIG_CLASSIFIER_BLOB,
		"a_config_blob", 0,
		&config2, sizeof(config2));

	CHECK_TRUE(success);
	UNSIGNED_LONGS_EQUAL(1, config_store_count(CONFIG_CLASSIFIER_DEVICE_REGION));
	UNSIGNED_LONGS_EQUAL(1, config_store_count(CONFIG_CLASSIFIER_BLOB));

	/* Expect queries for both objects to work */
	struct device_region query1_result;
	CHECK_TRUE(config_store_query(CONFIG_CLASSIFIER_DEVICE_REGION,
		config1.dev_class, config1.dev_instance,
		&query1_result, sizeof(query1_result)));

	struct config_blob query2_result;
	CHECK_TRUE(config_store_query(CONFIG_CLASSIFIER_BLOB,
		"a_config_blob", 0,
		&query2_result, sizeof(query2_result)));
}
