#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/stub_crypto_backend.c"
	)

# The stub crypto backend uses the psa crypto client to realize the
# psa crypto API that the crypto provider depends on.  This define
# configures the psa crypto client to be built with the stub crypto
# caller.
target_compile_definitions(${TGT} PRIVATE
	PSA_CRYPTO_CLIENT_CALLER_SELECTION_H="service/crypto/client/caller/stub/crypto_caller.h"
)
