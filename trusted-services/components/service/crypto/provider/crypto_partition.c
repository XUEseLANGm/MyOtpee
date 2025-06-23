/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "crypto_partition.h"

key_id_namespace_t crypto_partition_get_namespace(uint32_t client_id)
{
	/*
	 * Current just use the client_id as the namespace so keys are strictly
	 * partitioned by client id.
	 */
	return (key_id_namespace_t)client_id;
}

namespaced_key_id_t crypto_partition_get_namespaced_key_id(uint32_t client_id, psa_key_id_t key_id)
{
	namespaced_key_id_t ns_id = NAMESPACED_KEY_ID_INIT;

	namespaced_key_id_init(&ns_id, crypto_partition_get_namespace(client_id), key_id);

	return ns_id;
}

void crypto_partition_bind_to_owner(psa_key_attributes_t *attributes, uint32_t client_id)
{
	key_id_namespace_t ns = crypto_partition_get_namespace(client_id);

	namespaced_key_id_set_namespace(attributes, ns);
}
