/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <platform/interface/trng.h>

/*
 * A platform trng driver that provides a mock implementation that
 * always returns a fixed value.  Intended for test purposes only.
 */
static int mock_poll(void *context, unsigned char *output, size_t nbyte, size_t *len)
{
    (void)context;
    (void)output;

    *len = 0;

    if (nbyte < sizeof(unsigned char) )
        return 0;

    *len = sizeof(unsigned char);

    return 0;
}

int platform_trng_create(struct platform_trng_driver *driver, int instance)
{
    static const struct platform_trng_iface iface =  { .poll = mock_poll };

    (void)instance;
    driver->context = NULL;
    driver->iface = &iface;

    return 0;
}

void platform_trng_destroy(struct platform_trng_driver *driver)
{
    (void)driver;
}
