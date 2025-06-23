/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_PLATFORM_INTERFACE_TRNG_H
#define TS_PLATFORM_INTERFACE_TRNG_H

/*
 * Interface definintion for a platform trng driver.  A platform provider will
 * provide concrete implementations of this interface for each alternative
 * implementation supported.
 */
#include <stddef.h>
#include "device_region.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Virtual interface for a platform trng driver.  A platform will provide
 * one or more concrete implementations of this interface.
 */
struct platform_trng_iface
{
   /**
    * \brief Poll for bytes of entropy from a platform trng
    *
    * \param context     Platform driver context
    * \param output      Buffer for output
    * \param nbyte       Desired number of bytes
    * \param len         The number of bytes returned (could be zero)
    *
    * \return            0 if successful.
    */
    int (*poll)(void *context, unsigned char *output, size_t nbyte, size_t *len);
};

/*
 * A platform trng driver instance.
 */
struct platform_trng_driver
{
    void *context;                              /**< Opaque driver context */
    const struct platform_trng_iface *iface;  /**< Interface methods */
};

/**
 * \brief Factory method to construct a platform specific trng driver
 *
 * \param driver    Pointer to driver structure to initialize on construction.
 * \param instance    Deployment specific trng instance.
 *
 * \return          0 if successful.
 */
int platform_trng_create(struct platform_trng_driver *driver, int instance);

/**
 * \brief Destroy a driver constructed using the factory method
 *
 * \param driver    Pointer to driver structure for constructed driver.
 */
void platform_trng_destroy(struct platform_trng_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* TS_PLATFORM_INTERFACE_TRNG_H */
