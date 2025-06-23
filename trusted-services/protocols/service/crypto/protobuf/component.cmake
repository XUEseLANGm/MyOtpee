#-------------------------------------------------------------------------------
# Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

set_property(TARGET ${TGT} APPEND PROPERTY PROTOBUF_FILES
	"${CMAKE_CURRENT_LIST_DIR}/asymmetric_decrypt.proto"
	"${CMAKE_CURRENT_LIST_DIR}/asymmetric_encrypt.proto"
	"${CMAKE_CURRENT_LIST_DIR}/destroy_key.proto"
	"${CMAKE_CURRENT_LIST_DIR}/export_key.proto"
	"${CMAKE_CURRENT_LIST_DIR}/export_public_key.proto"
	"${CMAKE_CURRENT_LIST_DIR}/generate_key.proto"
	"${CMAKE_CURRENT_LIST_DIR}/generate_random.proto"
	"${CMAKE_CURRENT_LIST_DIR}/import_key.proto"
	"${CMAKE_CURRENT_LIST_DIR}/key_attributes.proto"
	"${CMAKE_CURRENT_LIST_DIR}/opcodes.proto"
	"${CMAKE_CURRENT_LIST_DIR}/sign_hash.proto"
	"${CMAKE_CURRENT_LIST_DIR}/verify_hash.proto"
	)
