#-------------------------------------------------------------------------------
# Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_include_directories(${TGT} PRIVATE
	"${MBEDTLS_INSTALL_DIR}/include"
)
target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/mbedcrypto_backend.c"
	)

# Use secure storage client to realize PSA ITS C API used by libmbedcrypto for
# persistent key storage.
set(MBEDTLS_EXTRA_INCLUDES
	"${TS_ROOT}/components/service/common/include"
	"${TS_ROOT}/components/service/secure_storage/include"
	CACHE STRING "PSA ITS for MbedTLS" FORCE)

# Override the default crypto backend interface with an alternative that is
# compatible with the configuration of mbedtls that this component imposes.
target_compile_definitions(${TGT} PUBLIC
	ALTERNATIVE_CRYPTO_BACKEND="${CMAKE_CURRENT_LIST_DIR}/mbedtls_psa_crypto_backend.h"
	)
