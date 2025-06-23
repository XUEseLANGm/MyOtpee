/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef CMD_UPDATE_IMAGE_H
#define CMD_UPDATE_IMAGE_H

#include <string>

#include "app/fwu_app.h"

int cmd_update_image(fwu_app &app, const std::string &img_type_uuid,
		     const std::string &img_filename);

#endif /* CMD_UPDATE_IMAGE_H */
