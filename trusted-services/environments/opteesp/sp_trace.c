// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#include "trace.h"
#include "ffa_api.h"
#include <string.h>

#if TRACE_LEVEL >= TRACE_LEVEL_ERROR

void trace_puts(const char *str)
{
	size_t length = strlen(str);
	size_t i = 0;

	for (i = 0; i < length; i += FFA_CONSOLE_LOG_64_MAX_LENGTH) {
		ffa_console_log_64(&str[i], MIN(FFA_CONSOLE_LOG_64_MAX_LENGTH,
						length - i));
	}
}

#endif  /* TRACE_LEVEL >= TRACE_LEVEL_ERROR */
