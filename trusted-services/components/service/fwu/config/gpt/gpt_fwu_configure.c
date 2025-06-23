/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "gpt_fwu_configure.h"

#include <errno.h>
#include <stdint.h>

#include "media/disk/gpt_iterator/gpt_iterator.h"
#include "media/disk/guid.h"
#include "media/volume/factory/volume_factory.h"
#include "media/volume/index/volume_index.h"
#include "service/fwu/fw_store/banked/volume_id.h"
#include "service/fwu/installer/factory/installer_factory.h"
#include "service/fwu/installer/installer.h"
#include "service/fwu/installer/installer_index.h"
#include "trace.h"

static struct installer *
create_and_register_installers(const struct uuid_octets *partition_type_uuid,
			       unsigned int location_id);

static int create_and_register_metadata_volume(const struct uuid_octets *device_uuid,
					       gpt_entry_t *entry, unsigned int *metadata_count);

int gpt_fwu_configure(const struct uuid_octets *device_uuid, unsigned int initial_location_id,
		      unsigned int *location_count)
{
	struct uuid_octets gpt_guid;
	unsigned int next_location_id = initial_location_id;
	unsigned int metadata_partition_count = 0;

	*location_count = 0;

	uuid_guid_octets_from_canonical(&gpt_guid, DISK_GUID_UNIQUE_PARTITION_DISK_HEADER);
	struct volume *gpt_volume = volume_factory_create_volume(&gpt_guid, device_uuid);

	if (!gpt_volume) {
		/* The case where there is no GPT volume is not necessarily an error.
		 * It could just mean that an alternative configuration method is required
		 * for this storage device.
		 */
		IMSG("No disk header volume");
		return 0;
	}

	/* Attempt to initialise a gpt_iterator. This requires a well-formed GPT to
	 * be present. Again, if there's not one, this is shouldn't be treated as
	 * an error as an alternative configuration method may be used,
	 */
	struct gpt_iterator gpt_iter;
	int status = gpt_iterator_init(&gpt_iter, gpt_volume);

	if (status) {
		IMSG("No GPT found");
		status = 0;
		goto abnormal_exit;
	}

	/* Iterate over partition table and extend configuration for updatable partitions */
	gpt_iterator_first(&gpt_iter);

	while (!gpt_iterator_is_done(&gpt_iter)) {
		gpt_entry_t entry;

		status = gpt_iterator_current(&gpt_iter, &entry);

		if (status) {
			EMSG("Failed to read GPT entry: %d", status);
			goto abnormal_exit;
		}

		const struct uuid_octets *partition_type_guid =
			(const struct uuid_octets *)&entry.type_uuid;

		/* Skip unused entry */
		if (uuid_is_nil(partition_type_guid->octets)) {
			gpt_iterator_next(&gpt_iter);
			continue;
		}

		/* Determine if any installers are available to handle some form of
		 * image installation for the location reflected by the partition type
		 * GUID. If a partition of the same type has already been encountered
		 * and the installation is supported, there will already be one or more
		 * registered installers.
		 */
		struct installer *installer =
			installer_index_find_by_location_uuid(partition_type_guid);

		if (!installer) {
			/* No installer for the partition type has yet been registered. This
			 * is either because this is the first partition of this type to be
			 * encountered or because the partition is not updatable. Find out by
			 * attempting to construct one or more installers.
			 */
			installer = create_and_register_installers(partition_type_guid,
								   next_location_id);

			if (installer)
				++next_location_id;
		}

		if (installer) {
			/* This configurator relies on the partition name to identify the bank
			 * index that the partition corresponds to. This convention also needs
			 * to be used by the bootloader to ensure that there is a consistent
			 * view of bank index. The name should include the bank index as the
			 * first character e.g. 0:AP-FW.
			 */
			unsigned int bank_index;

			if (entry.name[0] == '0')
				bank_index = 0;
			else if (entry.name[0] == '1')
				bank_index = 1;
			else {
				EMSG("Invalid bank index in partition name");
				goto abnormal_exit;
			}

			/* This partition is updatable so construct and register a volume
			 * to provide access to storage.
			 */
			struct volume *volume = volume_factory_create_volume(
				(const struct uuid_octets *)&entry.unique_uuid, device_uuid);

			if (!volume) {
				EMSG("Failed to create volume");
				goto abnormal_exit;
			}

			status = volume_index_add(banked_volume_id(installer->location_id,
								   banked_usage_id(bank_index)),
						  volume);

			if (status) {
				volume_factory_destroy_volume(volume);
				EMSG("Failed to register volume");
				goto abnormal_exit;
			}

		} else {
			/* Not an updatable partition but it might be for FWU metadata */
			status = create_and_register_metadata_volume(device_uuid, &entry,
								     &metadata_partition_count);

			if (status) {
				EMSG("Failed to create metadata volume");
				goto abnormal_exit;
			}
		}

		gpt_iterator_next(&gpt_iter);
	}

abnormal_exit:
	gpt_iterator_deinit(&gpt_iter);
	volume_factory_destroy_volume(gpt_volume);

	/* Count of the number of new locations added */
	*location_count = next_location_id - initial_location_id;

	return status;
}

static struct installer *
create_and_register_installers(const struct uuid_octets *partition_type_uuid,
			       unsigned int location_id)
{
	/* Attempt to create a complete set of installers for updating images
	 * contained within a partition of the specified type. The installer_factory
	 * holds the policy over which partitions are updatable and with what type
	 * of installer. If at least one installer ends up being constructed,
	 * a pointer to any of the constructed installers is returned.
	 */
	struct installer *last_constructed = NULL;
	struct installer *installer = NULL;

	installer = installer_factory_create_installer(INSTALL_TYPE_WHOLE_VOLUME, location_id,
						       partition_type_uuid);

	if (installer) {
		installer_index_register(installer);
		last_constructed = installer;
	}

	installer = installer_factory_create_installer(INSTALL_TYPE_SUB_VOLUME, location_id,
						       partition_type_uuid);

	if (installer) {
		installer_index_register(installer);
		last_constructed = installer;
	}

	installer = installer_factory_create_installer(INSTALL_TYPE_WHOLE_VOLUME_COPY, location_id,
						       partition_type_uuid);

	if (installer) {
		installer_index_register(installer);
		last_constructed = installer;
	}

	return last_constructed;
}

static int create_and_register_metadata_volume(const struct uuid_octets *device_uuid,
					       gpt_entry_t *entry, unsigned int *metadata_count)
{
	struct uuid_octets guid;

	uuid_guid_octets_from_canonical(&guid, DISK_GUID_PARTITION_TYPE_FWU_METADATA);

	if (!uuid_is_equal(guid.octets, (const uint8_t *)&entry->type_uuid))
		return 0;

	uint32_t volume_id;

	if (*metadata_count == 0)
		volume_id = BANKED_VOLUME_ID_PRIMARY_METADATA;
	else if (*metadata_count == 1)
		volume_id = BANKED_VOLUME_ID_BACKUP_METADATA;
	else
		/* Ignore any additional metadata partitions */
		return 0;

	struct volume *volume = volume_factory_create_volume(
		(const struct uuid_octets *)&entry->unique_uuid, device_uuid);

	if (!volume)
		return -EIO;

	if (volume_index_add(volume_id, volume)) {
		volume_factory_destroy_volume(volume);
		return -EIO;
	}

	*metadata_count += 1;

	return 0;
}