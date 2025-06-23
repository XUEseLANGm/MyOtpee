/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_ATTESTATION_EXPORT_IAK_PUBLIC_KEY_H
#define TS_ATTESTATION_EXPORT_IAK_PUBLIC_KEY_H

/**
 * Parameter definitions for the EXPORT_IAK_PUBLIC_KEY operation.
 *
 * Can be used during device provisioning to retrieve an
 * imported or generated IAK public key.  The IAK public key
 * may be used by a verifier as the identity for the device.
 * This operation supports the provisioning flow where the
 * IAK public key is read and stored in a central database.
 * Note that exporting the IAK public key from a device that
 * doesn't hold an IAK will trigger generation of a fresh
 * IAK using the device's TRNG.
 */

/* Variable length output parameter tags */
enum
{
    /* TLV tag to identify the IAK public key data parameter
     */
    TS_ATTESTATION_EXPORT_IAK_PUBLIC_KEY_OUT_TAG_DATA  = 1
};

#endif /* TS_ATTESTATION_EXPORT_IAK_PUBLIC_KEY_H */
