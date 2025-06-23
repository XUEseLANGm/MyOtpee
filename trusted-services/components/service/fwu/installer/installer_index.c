/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "installer_index.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "installer.h"
#include "trace.h"

#ifndef INSTALLER_INDEX_LIMIT
#define INSTALLER_INDEX_LIMIT (8)
#endif

#ifndef INSTALLER_INDEX_LOCATION_ID_LIMIT
#define INSTALLER_INDEX_LOCATION_ID_LIMIT (8)
#endif

/**
 * Singleton index of installers to use for different classes of image.
 */
static struct {
	/* An index for registered installers to handle update installation
	 * for the platform. The set of registered installers will have been
	 * selected for compatibility with the class of update image handled
	 * by the installer.
	 */
	size_t num_registered;
	struct installer *installers[INSTALLER_INDEX_LIMIT];

	/* Each installer is associated with a location via the assigned
	 * location_id. This is used as a logical identifier for the part
	 * of the device firmware that the installer handles. Multiple
	 * installers may be associated with the same location.
	 */
	size_t num_location_ids;
	uint32_t location_ids[INSTALLER_INDEX_LOCATION_ID_LIMIT];

} installer_index;

static void add_location_id(uint32_t location_id)
{
	/* Check if location_id already added. Because 1..* installers
	 * may be associated with the same location_id, we can ignore
	 * location_ids that have already been added.
	 */
	for (size_t i = 0; i < installer_index.num_location_ids; i++) {
		if (location_id == installer_index.location_ids[i])
			return;
	}

	/* It's a new location_id so add it */
	if (installer_index.num_location_ids < INSTALLER_INDEX_LOCATION_ID_LIMIT) {
		installer_index.location_ids[installer_index.num_location_ids] = location_id;
		++installer_index.num_location_ids;
	} else {
		EMSG("Too many FWU locations");
	}
}

void installer_index_init(void)
{
	installer_index_clear();
}

void installer_index_clear(void)
{
	memset(&installer_index, 0, sizeof(installer_index));
}

void installer_index_register(struct installer *installer)
{
	assert(installer);

	if (installer_index.num_registered < INSTALLER_INDEX_LIMIT) {
		installer_index.installers[installer_index.num_registered] = installer;
		++installer_index.num_registered;

		add_location_id(installer->location_id);
	} else {
		EMSG("FWU configuration exceeds installer limit");
	}
}

struct installer *installer_index_find(enum install_type install_type, uint32_t location_id)
{
	struct installer *result = NULL;

	for (size_t i = 0; i < installer_index.num_registered; i++) {
		struct installer *installer = installer_index.installers[i];

		if ((installer->install_type == install_type) &&
		    (installer->location_id == location_id)) {
			result = installer;
			break;
		}
	}

	return result;
}

struct installer *installer_index_find_by_location_uuid(const struct uuid_octets *location_uuid)
{
	struct installer *result = NULL;

	for (size_t i = 0; i < installer_index.num_registered; i++) {
		struct installer *installer = installer_index.installers[i];

		if (uuid_is_equal(location_uuid->octets, installer->location_uuid.octets)) {
			result = installer;
			break;
		}
	}

	return result;
}

struct installer *installer_index_get(unsigned int index)
{
	struct installer *result = NULL;

	if (index < installer_index.num_registered)
		result = installer_index.installers[index];

	return result;
}

const uint32_t *installer_index_get_location_ids(size_t *num_ids)
{
	*num_ids = installer_index.num_location_ids;
	return installer_index.location_ids;
}
