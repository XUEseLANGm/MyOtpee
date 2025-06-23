/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LOG_BACKEND_H
#define LOG_BACKEND_H

#include "components/service/log/common/log_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Common log backend interface
 *
 * A concrete log backend provides an implementation of this
 * interface.
 */
struct log_backend_interface {
	/**
	* \brief Processes the character sequence (str) in a desired way (e.g. print to UART).
	*
	* \param[in]  context	The concrete backend context
	* \param[in]  str	Character sequence to be printed (null-terminated)
	*/
	log_status_t (*puts)(void *context, const char *str);
};

/**
 * \brief Common log backend instance
 */
struct log_backend {
	/**
	* \brief The backend context
	*
	* Points to backend specific instance data.
	*/
	void *context;

	/**
	* \brief The backend interface
	*
	* A concrete backend provides an implementation of this interface.
	*/
	const struct log_backend_interface *interface;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LOG_BACKEND_H */
