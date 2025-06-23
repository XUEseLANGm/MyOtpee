/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "carveout.h"

#ifndef MM_COMM_BUFFER_ADDRESS
#error "MM_COMM_BUFFER_ADDRESS macro is undefined!"
#endif
#ifndef MM_COMM_BUFFER_SIZE
#error "MM_COMM_BUFFER_SIZE macro is undefined!"
#endif

int carveout_claim(uint8_t **buf, size_t *buf_size)
{
	int status = -1;
	int fd = open("/dev/mem", O_RDWR | O_SYNC);

	if (fd >= 0) {

		uint8_t *mem = mmap(NULL, (size_t)(MM_COMM_BUFFER_SIZE),
			PROT_READ | PROT_WRITE, MAP_SHARED,
			fd, (off_t)(MM_COMM_BUFFER_ADDRESS));

		if (mem != MAP_FAILED) {

			*buf = mem;
			*buf_size = (size_t)(MM_COMM_BUFFER_SIZE);

			status = 0;
		}

		close(fd);
	}

	return status;
}

void carveout_relinquish(uint8_t *buf, size_t buf_size)
{
	munmap(buf, buf_size);
}
