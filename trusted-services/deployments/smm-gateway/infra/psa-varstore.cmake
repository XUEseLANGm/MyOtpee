#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# An infrastrucure to support the smm-gateway. Uses PSA storage for persistent
# storage of NV UEFI variables.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
# Infrastructure components
#
#-------------------------------------------------------------------------------
add_components(TARGET "smm-gateway"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/rpc/common/caller"
		"components/service/common/client"
		"components/service/locator"
		"components/service/locator/interface"
		"components/service/secure_storage/backend/secure_storage_client"
		"protocols/service/secure_storage/packed-c"
)
