/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef STORAGE_PARTITION_ACL_H
#define STORAGE_PARTITION_ACL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* By default, the ACL allowlist only accommodates a single client for
 * a storage partition. This may be overridden per deployment at build-time
 * if multiple clients need to be supported.
 */
#ifndef STORAGE_PARTITION_ACL_ALLOWLIST_LEN
#define STORAGE_PARTITION_ACL_ALLOWLIST_LEN     (1)
#endif

/* Default maximum owner ID string length */
#ifndef STORAGE_PARTITION_ACL_MAX_OWNER_ID_LEN
#define STORAGE_PARTITION_ACL_MAX_OWNER_ID_LEN  (40)
#endif

/* Forward declarations */
struct storage_partition_acl;

/**
 * \brief Authorizer function
 *
 * Implements deployment specific authorization policy and owner ID
 * resolution to determine if the presented client ID is allowed access.
 * A concrete authorizer may perform an environment specific discovery operation
 * to check if the presented client ID corresponds to the configured
 * owner ID.
 *
 * \param[in]  client_id    The presented client ID
 * \param[in]  owner_id		The configured owner ID
 * \return True if client_id is permitted access
 */
typedef bool (*storage_partition_authorizer)(
	uint32_t client_id,
	const char *owner_id);

/**
 * \brief Storage partition access control list
 *
 * Access to a storage partition may be controlled by either adding specific
 * client IDs to the access control list or by providing an authorizer function
 * that will resolve the owner ID string to a set of client IDs. The authorizer
 * allows for lazy resolution for an owner ID to client ID at the point that
 * a client attempts to open a partition but its client ID is not present in
 * the ACL.
 */
struct storage_partition_acl {
	char owner_id[STORAGE_PARTITION_ACL_MAX_OWNER_ID_LEN];
	size_t allowlist_len;
	uint32_t allowlist[STORAGE_PARTITION_ACL_ALLOWLIST_LEN];
};

/**
 * \brief Initialise an empty storage_partition_acl
 *
 * \param[in]  acl      The subject storage_partition_acl
 */
void storage_partition_acl_init(
	struct storage_partition_acl *acl);

/**
 * \brief Add a client ID to the ACL allowlist
 *
 * \param[in]  acl       The subject storage_partition_acl
 * \param[in]  client_id Client ID to add
 * \return True if added successfully
 */
bool storage_partition_acl_add(
	struct storage_partition_acl *acl,
	uint32_t client_id);

/**
 * \brief Set the owner ID string
 *
 * \param[in]  acl       The subject storage_partition_acl
 * \param[in]  owner_id  Owner ID string
 * \return True if successful
 */
bool storage_partition_acl_set_owner_id(
	struct storage_partition_acl *acl,
	const char *owner_id);

/**
 * \brief Check if a client has access permission
 *
 * \param[in]  acl       The subject storage_partition_acl
 * \param[in]  client_id Client ID to check
 *
 * \return True if access is permitted
 */
bool storage_partition_acl_check(
	const struct storage_partition_acl *acl,
	uint32_t client_id);

/**
 * \brief Authorize a requesting client
 *
 * \param[in]  acl        The subject storage_partition_acl
 * \param[in]  client_id  Client ID to check
 * \param[in]  authorizer Optional authorizer
 *
 * \return True if access is permitted
 */
bool storage_partition_acl_authorize(
	struct storage_partition_acl *acl,
	uint32_t client_id,
	storage_partition_authorizer authorizer);

#ifdef __cplusplus
}
#endif

#endif /* STORAGE_PARTITION_ACL_H */
