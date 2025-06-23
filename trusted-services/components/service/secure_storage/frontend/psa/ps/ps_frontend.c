/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ps_frontend.h"
#include <psa/protected_storage.h>


/* Singleton instance data */
static struct psa_ps_frontend
{
	struct storage_backend *backend;
	uint32_t client_id;
} instance;

psa_status_t psa_ps_frontend_init(struct storage_backend *backend)
{
	instance.backend = backend;
	instance.client_id = 0;

	return PSA_SUCCESS;
}

psa_status_t psa_ps_set(psa_storage_uid_t uid,
			 size_t data_length,
			 const void *p_data,
			 psa_storage_create_flags_t create_flags)
{
	return instance.backend->interface->set(
				instance.backend->context,
				instance.client_id,
				uid,
				data_length,
				p_data,
				create_flags);
}

psa_status_t psa_ps_get(psa_storage_uid_t uid,
			 size_t data_offset,
			 size_t data_size,
			 void *p_data,
			 size_t *p_data_length)
{
	return instance.backend->interface->get(
				instance.backend->context,
				instance.client_id,
				uid,
				data_offset,
				data_size,
				p_data,
				p_data_length);
}

psa_status_t psa_ps_get_info(psa_storage_uid_t uid,
				  struct psa_storage_info_t *p_info)
{
	return instance.backend->interface->get_info(
				instance.backend->context,
				instance.client_id,
				uid,
				p_info);
}

psa_status_t psa_ps_remove(psa_storage_uid_t uid)
{
	return instance.backend->interface->remove(
				instance.backend->context,
				instance.client_id,
				uid);
}

psa_status_t psa_ps_create(psa_storage_uid_t uid,
                size_t capacity,
                psa_storage_create_flags_t create_flags)
{
	return instance.backend->interface->create(
				instance.backend->context,
				instance.client_id,
				uid,
				capacity,
				create_flags);
}

psa_status_t psa_ps_set_extended(psa_storage_uid_t uid,
                size_t data_offset,
                size_t data_length,
                const void *p_data)
{
	return instance.backend->interface->set_extended(
				instance.backend->context,
				instance.client_id,
				uid,
				data_offset,
				data_length,
				p_data);
}

uint32_t psa_ps_get_support(void)
{
	return instance.backend->interface->get_support(
				instance.backend->context,
				instance.client_id);
}