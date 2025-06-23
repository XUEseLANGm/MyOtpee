/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <config/interface/config_store.h>
#include <platform/interface/trng.h>
#include <platform/interface/device_region.h>
#include <psa/error.h>
#include "juno_decl.h"

/*
 * A platform trng driver that uses the juno_trng driver from TF-A to provide a
 * hardware entropy source.
 */

static int trng_poll(void *context, unsigned char *output, size_t nbyte, size_t *len)
{
     int status = 0;

    *len = 0;

    if (nbyte >= sizeof(unsigned char)) {

        status = juno_getentropy(output, nbyte);

        if (status == 0) {
            *len = nbyte;
        }
        else {
            /* Mbedtls currently crashes when a failure status is returned.
             * This workaround prevents the crash for cases where no
             * configuration has been provided for the trng.
             */
            status = 0;
            *len = sizeof(unsigned char);
        }
    }

    return status;
}

int platform_trng_create(struct platform_trng_driver *driver, int instance)
{
    static const struct platform_trng_iface iface =  { .poll = trng_poll };
    struct device_region device_region;

    /*
     * Default to leaving the driver in a safe but inoperable state.
     */
    driver->iface = &iface;
    driver->context = NULL;

    if (!config_store_query(CONFIG_CLASSIFIER_DEVICE_REGION, "trng",
                            instance, &device_region,
                            sizeof(device_region)))
        return PSA_STATUS_HARDWARE_FAILURE;

   /*
    * A device region has been provided, possibly from an external configuation.
    */
   juno_trng_set_base_addr(device_region.base_addr);

   return PSA_SUCCESS;
}

void platform_trng_destroy(struct platform_trng_driver *driver)
{
    (void)driver;
    juno_trng_set_base_addr(0);
}
