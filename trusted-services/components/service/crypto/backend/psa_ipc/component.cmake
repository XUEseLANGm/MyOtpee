#-------------------------------------------------------------------------------
# Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/crypto_ipc_backend.c"
	)

# The ipc crypto backend uses the psa crypto client to realize the
# psa crypto API that the crypto provider depends on.  This define
# configures the psa crypto client to be built with the ipc crypto
# caller.
target_compile_definitions(${TGT} PRIVATE
	PSA_CRYPTO_CLIENT_CALLER_SELECTION_H="service/crypto/client/caller/psa_ipc/crypto_caller.h"
)
