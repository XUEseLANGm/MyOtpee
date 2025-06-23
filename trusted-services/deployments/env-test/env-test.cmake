#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  The base build file shared between deployments of 'env-test' for
#  different environments.  Used for running tests that validate hardwarw
#  backed services available from within a secure execution environment.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  Components that are common across all deployments
#
#-------------------------------------------------------------------------------
add_components(
	TARGET "env-test"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
	"components/common/tlv"
	"components/rpc/common/interface"
	"components/service/common/include"
	"components/service/common/provider"
	"components/service/test_runner/provider"
	"components/service/test_runner/provider/serializer/packed-c"
	"components/service/test_runner/provider/backend/null"
	"components/service/test_runner/provider/backend/simple_c"
	"protocols/rpc/common/packed-c"
)

target_include_directories(env-test PRIVATE
	${TS_ROOT}
	${TS_ROOT}/components
)

