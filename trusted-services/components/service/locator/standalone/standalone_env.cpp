/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service_locator.h>
#include <service/locator/standalone/services/crypto/crypto_service_context.h>
#include <service/locator/standalone/services/internal-trusted-storage/its_service_context.h>
#include <service/locator/standalone/services/protected-storage/ps_service_context.h>
#include <service/locator/standalone/services/test-runner/test_runner_service_context.h>
#include <service/locator/standalone/services/attestation/attestation_service_context.h>
#include <service/locator/standalone/services/block-storage/block_storage_service_context.h>
#include <service/locator/standalone/services/fwu/fwu_service_context.h>
#include <service/locator/standalone/services/smm-variable/smm_variable_service_context.h>
#include <service/locator/standalone/services/rpmb/rpmb_service_context.h>
#include "standalone_location_strategy.h"
#include "standalone_service_registry.h"

void service_locator_envinit(void)
{
	static crypto_service_context crypto_context("sn:trustedfirmware.org:crypto:0", TS_RPC_ENCODING_PACKED_C);
	standalone_service_registry::instance()->regsiter_service_instance(&crypto_context);

	static crypto_service_context crypto_context_protobuf("sn:trustedfirmware.org:crypto-protobuf:0",
							      TS_RPC_ENCODING_PROTOBUF);
	standalone_service_registry::instance()->regsiter_service_instance(&crypto_context_protobuf);

	static its_service_context its_service_context("sn:trustedfirmware.org:internal-trusted-storage:0");
	standalone_service_registry::instance()->regsiter_service_instance(&its_service_context);

	static ps_service_context ps_service_context("sn:trustedfirmware.org:protected-storage:0");
	standalone_service_registry::instance()->regsiter_service_instance(&ps_service_context);

	static test_runner_service_context test_runner_context("sn:trustedfirmware.org:test-runner:0");
	standalone_service_registry::instance()->regsiter_service_instance(&test_runner_context);

	static attestation_service_context attestation_context("sn:trustedfirmware.org:attestation:0");
	standalone_service_registry::instance()->regsiter_service_instance(&attestation_context);

	static block_storage_service_context block_storage_context("sn:trustedfirmware.org:block-storage:0");
	standalone_service_registry::instance()->regsiter_service_instance(&block_storage_context);

	static fwu_service_context fwu_context("sn:trustedfirmware.org:fwu:0");
	standalone_service_registry::instance()->regsiter_service_instance(&fwu_context);

	static smm_variable_service_context smm_variable_context("sn:trustedfirmware.org:smm-variable:0");
	standalone_service_registry::instance()->regsiter_service_instance(&smm_variable_context);

	static rpmb_service_context rpmb_context("sn:trustedfirmware.org:rpmb:0");
	standalone_service_registry::instance()->regsiter_service_instance(&rpmb_context);

	service_locator_register_strategy(standalone_location_strategy());
}
