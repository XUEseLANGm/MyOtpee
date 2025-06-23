/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <mbedtls/entropy.h>
#include <service/crypto/backend/mbedcrypto/trng_adapter/trng_adapter.h>
#include <psa/error.h>
#include <unistd.h>
#include <linux/random.h>
#include <sys/random.h>
#include <errno.h>

/*
 * An mbed tls compatibile hardware entropy source that adapts the mbed tls hardware poll
 * function to the Linux getrandom system call.
 */

int trng_adapter_init(int instance)
{
    (void)instance;
    return PSA_SUCCESS;
}

void trng_adapter_deinit()
{

}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    (void)data;

    int status = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    *olen = 0;

    /*
     * Use the GRND_INSECURE flag so the call won't block even if there is not
     * enough entropy available at the time of the syscall, so the crng wasn't
     * initialized yet. Returns possibly cryptographically insecure random data,
     * which is fine for testing purposes.
     */
    int num_output = getrandom(output, len, GRND_INSECURE);

    if (num_output >= 0) {

        *olen = num_output;
        status = 0;
    }

    return status;
}
