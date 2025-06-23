/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <sys/stat.h>

#include "cmd_print_image_dir.h"
#include "cmd_print_metadata_v1.h"
#include "cmd_print_metadata_v2.h"
#include "cmd_update_image.h"
#include "common/uuid/uuid.h"
#include "app/fwu_app.h"

static bool option_selected(const char *option_switch, int argc, char *argv[]);

static std::string parse_string_option(const char *option_switch, int argc, char *argv[],
				       const char *default_val);

static int parse_numeric_option(const char *option_switch, int argc, char *argv[], int default_val);

static bool file_exists(const std::string &filename);

static void print_usage(void);
static void print_help(void);

int main(int argc, char *argv[])
{
	fwu_app app;
	std::string disk_img_filename;
	std::string update_img_filename;
	std::string img_type_uuid;

	/* Check for help */
	if (option_selected("-h", argc, argv) || option_selected("-help", argc, argv) ||
	    option_selected("--help", argc, argv)) {
		print_help();
		return 0;
	}

	/* Handle mandatory disk image filename. Must be first argument */
	if (argc > 1)
		disk_img_filename = std::string(argv[1]);
	else {
		printf("Error: missing disk-filename argument\n");
		print_usage();
		return -1;
	}

	/* Check if disk image file exists */
	if (!file_exists(disk_img_filename)) {
		printf("Error: %s does not exist\n", disk_img_filename.c_str());
		return -1;
	}

	/* Create fwu configuration based on the input disk image */
	int status = app.configure(disk_img_filename.c_str());

	if (status) {
		printf("Error: failed to configure with status: %d\n", status);
		return -1;
	}

	/* Attempt to derive boot info from metadata. Assume bootloader booted from the
	 * active index. This can be overridden via command-line parameter.
	 */
	unsigned int boot_index;
	unsigned int metadata_version;

	status = app.get_boot_info(boot_index, metadata_version);

	if (status) {
		printf("No recognised metadata, assume default boot index and version\n");

		boot_index = 0;
		metadata_version = 2;
	}

	/* Allow for command-line overrides */
	boot_index = parse_numeric_option("-boot-index", argc, argv, boot_index);
	metadata_version = parse_numeric_option("-meta-ver", argc, argv, metadata_version);

	/* Options for printing fwu info */
	bool is_print_img_dir = option_selected("-dir", argc, argv);
	bool is_print_metadata = option_selected("-meta", argc, argv);

	/* Parse input image related parameters*/
	update_img_filename = parse_string_option("-img", argc, argv, "");
	img_type_uuid = parse_string_option("-img-type", argc, argv, "");

	/* Check if image file exists (if one was specified) */
	if (!update_img_filename.empty() && !file_exists(update_img_filename)) {
		printf("Error: %s does not exist\n", update_img_filename.c_str());
		return -1;
	}

	/* Check if img type canonical uuid is well formed */
	if (!img_type_uuid.empty() && !uuid_is_valid(img_type_uuid.c_str())) {
		printf("Error: image type uuid invalid\n");
		return -1;
	}

	/* Initialise the update_agent. Missing or corrupt metadata will get repaired
	 */
	status = app.init_update_agent(boot_index, metadata_version);

	if (!status) {
		printf("Update agent started: boot index: %u metadata ver: %u\n", boot_index,
		       metadata_version);

		if (is_print_img_dir)
			cmd_print_image_dir(app);

		if (is_print_metadata) {
			if (metadata_version == 1)
				cmd_print_metadata_v1(app);
			else if (metadata_version == 2)
				cmd_print_metadata_v2(app);
			else
				printf("Unsupported metadata version\n");
		}

		if (!update_img_filename.empty() && !img_type_uuid.empty()) {
			status = cmd_update_image(app, img_type_uuid, update_img_filename);

		} else if (!update_img_filename.empty() || !img_type_uuid.empty()) {
			printf("Error: both image filename and uuid arguments are needed\n");
			return -1;
		}
	}

	if (!status)
		printf("OK\n");
	else
		printf("Error status: %d\n", status);

	return status;
}

static bool option_selected(const char *option_switch, int argc, char *argv[])
{
	bool is_selected = false;

	for (int i = 1; (i < argc) && !is_selected; ++i) {
		is_selected = (strcmp(argv[i], option_switch) == 0);
	}

	return is_selected;
}

static std::string parse_string_option(const char *option_switch, int argc, char *argv[],
				       const char *default_val)
{
	std::string option = std::string(default_val);

	for (int i = 1; i + 1 < argc; ++i) {
		if (strcmp(argv[i], option_switch) == 0) {
			option = std::string(argv[i + 1]);
			break;
		}
	}

	return option;
}

static int parse_numeric_option(const char *option_switch, int argc, char *argv[], int default_val)
{
	int option = default_val;

	for (int i = 1; i + 1 < argc; ++i) {
		if (strcmp(argv[i], option_switch) == 0) {
			std::istringstream iss(argv[i + 1]);
			int val;

			iss >> val;

			if (!iss.fail())
				option = val;

			break;
		}
	}

	return option;
}

static bool file_exists(const std::string &filename)
{
	struct stat stat_buf;

	return stat(filename.c_str(), &stat_buf) == 0;
}

static void print_usage(void)
{
	printf("Usage: fwu disk-filename [-dir -meta] [-boot-index number -meta-ver number] "
	       "[-img filename -img-type uuid]\n");
}

static void print_help(void)
{
	print_usage();

	printf("\n");
	printf("\tdisk-filename\tDisk image file to update\n");
	printf("\t-dir\t\tPrint image directory\n");
	printf("\t-meta\t\tPrint FWU metadata\n");
	printf("\t-boot-index\tOverride default boot index [0..n]\n");
	printf("\t-meta-ver\tSpecify FWU metadata to use\n");
	printf("\t-img\t\tFile containing image update\n");
	printf("\t-img-type\tCanonical UUID of image to update\n");
}
