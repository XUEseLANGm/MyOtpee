#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Defines an infrastructure for the crypto service provider that uses a
# baremetal platform TRNG driver and PSA storage for persistent key storage.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Infrastructure components
#
#-------------------------------------------------------------------------------
add_components(TARGET "crypto"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/rpc/ts_rpc/caller/sp"
		"components/rpc/common/caller"
		"components/service/common/client"
		"components/service/crypto/backend/mbedcrypto/trng_adapter/platform"
		"components/service/secure_storage/include"
		"components/service/secure_storage/frontend/psa/its"
		"components/service/secure_storage/backend/secure_storage_client"
		"components/service/secure_storage/backend/null_store"
		"components/service/secure_storage/factory/sp/rot_store"
		"protocols/service/secure_storage/packed-c"
)

#-------------------------------------------------------------------------------
#  This infrastructure depends on platform specific drivers
#
#-------------------------------------------------------------------------------
add_platform(TARGET "crypto")
