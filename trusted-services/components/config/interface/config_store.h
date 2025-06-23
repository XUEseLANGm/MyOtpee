/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CONFIG_STORE_H
#define CONFIG_STORE_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Provides a common interface for retrieving configuration
 * objects.  Configuration objects are used at run-time
 * to configure TS deployments such as a service provider
 * running within a secure partition.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief A classifier for configuration objects
 *
 * Used as a label to identifier the general class of a configuartion object.
 */
enum config_classifier
{
	/* A classifier for a device region that describes a region of IO mapped memory */
	CONFIG_CLASSIFIER_DEVICE_REGION,

	/* A classifier for a memory region that describes a region of memory */
	CONFIG_CLASSIFIER_MEMORY_REGION,

	/* A classifier to describe a hardware feature's availability */
	CONFIG_CLASSIFIER_HW_FEATURE,

	/* A classifier for an opaque configuration blob */
	CONFIG_CLASSIFIER_BLOB
};


/**
 * \brief Query for a particular configuration object
 *
 * \param[in]  	classifier		The class of object
 * \param[in]  	name  			The name of the object
 * \param[in]  	instance		The instance number
 * \param[out]	data			Pointer to client provided buffer for the object
 * \param[in]	data_buf_size	Size of the client provided buffer
 *
 * \return	True if successful
 */
bool config_store_query(enum config_classifier classifier,
	const char *name,
	unsigned int instance,
	void *data,
	size_t data_buf_size);

/**
 * \brief Add an object to the config store
 *
 * \param[in]  	classifier		The class of object
 * \param[in]  	name  			The name of the object
 * \param[in]  	instance		The instance number
 * \param[in]	data			The object data to add
 * \param[in]	data_len		The size of the object
 *
 * \return	True if successful
 */
bool config_store_add(enum config_classifier classifier,
	const char *name,
	unsigned int instance,
	const void *data,
	size_t data_len);

/**
 * \brief Returns a count of the number of objects of a particular class
 *
 * \param[in]  	classifier		The class of object
 *
 * \return  Count of objects held
 */
unsigned int config_store_count(enum config_classifier classifier);


#ifdef __cplusplus
}
#endif

#endif /* CONFIG_STORE_H */
