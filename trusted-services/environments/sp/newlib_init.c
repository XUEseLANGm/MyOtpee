// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 */

#include "libc_init.h"

/* Comes from libc */
void __libc_init_array(void);

void _init(void)
{
	/* Dummy */
}

void libc_init(void)
{
	/* Initializing global variables, calling constructors */
	__libc_init_array();
}
