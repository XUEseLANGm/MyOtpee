/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LOCAL_ATTEST_KEY_MNGR_H
#define LOCAL_ATTEST_KEY_MNGR_H

#include <psa/crypto.h>

/* Key ID for a volatile IAK (for test) */
#define LOCAL_ATTEST_KEY_MNGR_VOLATILE_IAK            (0)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A local attestation key manager that manages the IAK on
 * behalf of a local reporter.  Used to support local signing
 * of reports.  The local_attest_key_mngr provides a
 * realization of the public interface defined in
 * attest_key_mngr.h.
 */

/**
 * \brief Initialize the local_attest_key_mngr
 *
 * Initializes the local_attest_key_mngr.  The provided key id should
 * be used as the identifier for the IAK.  If a key ID of zero
 * is passed, a volatile IAK will be generated.  This is useful
 * for test purposes.
 *
 * \param[in] cfg_iak_id    The configured IAK key id (zero for volatile)
 */
void local_attest_key_mngr_init(psa_key_id_t cfg_iak_id);

/**
 * \brief De-initialize the attest_key_mngr
 */
void local_attest_key_mngr_deinit(void);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LOCAL_ATTEST_KEY_MNGR_H */
