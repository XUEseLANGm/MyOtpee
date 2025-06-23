/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STANDALONE_ATTESTATION_SERVICE_CONTEXT_H
#define STANDALONE_ATTESTATION_SERVICE_CONTEXT_H

#include <service/locator/standalone/standalone_service_context.h>
#include <rpc/direct/direct_caller.h>
#include <service/attestation/provider/attest_provider.h>
#include <service/attestation/claims/sources/event_log/event_log_claim_source.h>
#include <service/attestation/claims/sources/boot_seed_generator/boot_seed_generator.h>
#include <service/attestation/claims/sources/null_lifecycle/null_lifecycle_claim_source.h>
#include <service/attestation/claims/sources/instance_id/instance_id_claim_source.h>
#include <service/attestation/claims/sources/implementation_id/implementation_id_claim_source.h>

class attestation_service_context : public standalone_service_context
{
public:
    attestation_service_context(const char *sn);
    virtual ~attestation_service_context();

private:

    void do_init();
    void do_deinit();

    void open_crypto_session();
    void close_crypto_session();


    struct attest_provider m_attest_provider;
    struct event_log_claim_source m_event_log_claim_source;
    struct boot_seed_generator m_boot_seed_claim_source;
    struct null_lifecycle_claim_source m_lifecycle_claim_source;
    struct instance_id_claim_source m_instance_id_claim_source;
    struct implementation_id_claim_source m_implementation_id_claim_source;
    struct service_context *m_crypto_service_context;
    struct rpc_caller_session *m_crypto_session;
};

#endif /* STANDALONE_ATTESTATION_SERVICE_CONTEXT_H */
