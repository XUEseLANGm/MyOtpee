/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_ATTESTATION_IMPORT_IAK_H
#define TS_ATTESTATION_IMPORT_IAK_H

/**
 * Parameter definitions for the IMPORT_IAK operation.
 *
 * Used during device provisioning to load an externally
 * generated IAK key-pair into a device.  An attempt to
 * import an IAK when an IAK already exists will be rejected.
 */

/* Variable length input parameter tags */
enum
{
    /* TLV tag to identify the IAK key-pair data parameter
     */
    TS_ATTESTATION_IMPORT_IAK_IN_TAG_DATA  = 1,
};

#endif /* TS_ATTESTATION_IMPORT_IAK_H */
