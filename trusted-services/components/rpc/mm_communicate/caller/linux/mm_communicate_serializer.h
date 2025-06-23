/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MM_COMMUNICATE_SERIALIZER_H
#define MM_COMMUNICATE_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include <protocols/common/efi/efi_status.h>
#include "protocols/common/efi/efi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Provides an interface for encoding/decoding the MM Communicate and
 * MM service specific headers. Based on the TS view of an RPC layer
 * RPC related parameters are distributed between the generic
 * MM Communicate header and the SMM service specific header.
 * Concrete functions are determined by the requests SMM service GUID.
 */
struct mm_communicate_serializer;

/**
 * \brief Find a MM Communicate serializer
 *
 *  Find a serializer for the specified service GUID.
 *
 * \param[in] svc_guid  The SMM service GUID
 *
 * \return Pointer to serializer or NULL if not found
 */
const struct mm_communicate_serializer *mm_communicate_serializer_find(
	const EFI_GUID *svc_guid);

/**
 * \brief Return the header size for the specified serializer
 *
 * \param[in] serializer  The concrete serializer
 *
 * \return Header size comprising MM Communicate header + SMM service header
 */
size_t mm_communicate_serializer_header_size(
	const struct mm_communicate_serializer *serializer);

/**
 * \brief Encode the MM Communicate + SMM service header
 *
 * \param[in] serializer Concrete serializer
 * \param[in] buf       Encode to this buffer
 * \param[in] opcode    Service opcode
 * \param[in] req_len   Length of the request
 */
void mm_communicate_serializer_header_encode(
	const struct mm_communicate_serializer *serializer,
	uint8_t *buf,
	uint32_t opcode,
	size_t req_len);

/**
 * \brief Header decode function
 *
 * \param[in] serializer Concrete serializer
 * \param[in] buf       Encode to this buffer
 * \param[out] efi_status EFI status code
 * \param[out] resp_buf Response buffer
 * \param[out] resp_len Length of the response
 */
void mm_communicate_serializer_header_decode(
	const struct mm_communicate_serializer *serializer,
	uint8_t *buf,
	efi_status_t *efi_status,
	uint8_t **resp_buf,
	size_t *resp_len);

#ifdef __cplusplus
}
#endif

#endif /* MM_COMMUNICATE_SERIALIZER_H */
