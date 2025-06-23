/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SERVICE_NAME_H
#define SERVICE_NAME_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Check if it is valid service name with all the mandatory sections.
 */
bool sn_is_valid(const char *sn);

/*
 * Check naming authority. Returns true for match.
 */
bool sn_check_authority(const char *sn, const char *auth);

/*
 * Check the service portion of the service name. Returns true for match.
 */
bool sn_check_service(const char *sn, const char *service);

/*
 * Get the service instance number
 */
unsigned int sn_get_service_instance(const char *sn);

/*
 * Read the service field and copy the null terminated string
 * to the provided buffer.  Returns the copied string length,
 * minus the zero terminator.
 */
size_t sn_read_service(const char *sn, char *buf, size_t buf_len);


#ifdef __cplusplus
}
#endif

#endif /* SERVICE_NAME_H */
