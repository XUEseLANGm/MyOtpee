/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <string.h>
#include <protocols/service/smm_variable/smm_variable_proto.h>
#include <protocols/common/efi/efi_types.h>
#include "mm_communicate_serializer.h"

/* Concrete service header serialization functions */
static void smm_variable_header_encode(const struct mm_communicate_serializer *serializer,
	uint8_t *buf, uint32_t opcode);
static void smm_variable_header_decode(const struct mm_communicate_serializer *serializer,
	uint8_t *buf, efi_status_t *efi_status);

/**
 * Rather than have a generic RPC header, header parameters are
 * split between the generic MM Communicate header and an SMM
 * service specific header that carries the function ID to
 * call and the return status. To accommodate different
 * service specific headers, concrete header encode/decode
 * functions are provided, keyed off the service guid
 * carried in the MM Communicate header.
 */
struct mm_communicate_serializer
{
	/**
	 * \brief The service GUID
	 */
	EFI_GUID svc_guid;

	/**
	 * \brief Service header size
	 */
	size_t svc_header_size;

	/**
	 * \brief Service header encode function
	 *
	 * \param[in] serializer Concrete serializer
	 * \param[in] buf       Encode to this buffer
	 * \param[in] opcode    Service opcode
	 */
	void (*header_encode)(
		const struct mm_communicate_serializer *serializer,
		uint8_t *buf,
		uint32_t opcode);

	/**
	 * \brief Header decode function
	 *
	 * \param[in] serializer Concrete serializer
	 * \param[in] buf       Encode to this buffer
	 * \param[out] efi_status EFI status code
	 */
	void (*header_decode)(
		const struct mm_communicate_serializer *serializer,
		uint8_t *buf,
		efi_status_t *efi_status);
};

const struct mm_communicate_serializer *mm_communicate_serializer_find(const EFI_GUID *svc_guid)
{
	/* Lookup to map service guid to a concrete serializer */
	static const struct mm_communicate_serializer lookup[] =
	{
		/* SMM Variable mapping */
		{
			SMM_VARIABLE_GUID,
			SMM_VARIABLE_COMMUNICATE_HEADER_SIZE,
			smm_variable_header_encode,
			smm_variable_header_decode
		}
	};

	/* Find a concrete mapping for the requested service */
	for (size_t i = 0; i < sizeof(lookup)/sizeof(struct mm_communicate_serializer); ++i) {

		const struct mm_communicate_serializer *serializer =  &lookup[i];

		if ((svc_guid->Data1 == serializer->svc_guid.Data1) &&
			(svc_guid->Data2 == serializer->svc_guid.Data2) &&
			(svc_guid->Data3 == serializer->svc_guid.Data3) &&
			(memcmp(svc_guid->Data4, serializer->svc_guid.Data4, sizeof(svc_guid->Data4)) == 0)) {

			return serializer;
		}
	}

	/* Failed to find serializer */
	return NULL;
}

size_t mm_communicate_serializer_header_size(
	const struct mm_communicate_serializer *serializer)
{
	return EFI_MM_COMMUNICATE_HEADER_SIZE + serializer->svc_header_size;
}

void mm_communicate_serializer_header_encode(
	const struct mm_communicate_serializer *serializer,
	uint8_t *buf,
	uint32_t opcode,
	size_t req_len)
{
	EFI_MM_COMMUNICATE_HEADER *hdr = (EFI_MM_COMMUNICATE_HEADER*)buf;
	hdr->HeaderGuid = serializer->svc_guid;
	hdr->MessageLength = serializer->svc_header_size + req_len;

	/* Encode the service specific header */
	serializer->header_encode(serializer, hdr->Data, opcode);
}

void mm_communicate_serializer_header_decode(
	const struct mm_communicate_serializer *serializer,
	uint8_t *buf,
	efi_status_t *efi_status,
	uint8_t **resp_buf,
	size_t *resp_len)
{
	EFI_MM_COMMUNICATE_HEADER *hdr = (EFI_MM_COMMUNICATE_HEADER*)buf;

	*efi_status = EFI_PROTOCOL_ERROR;
	*resp_len = 0;

	if (hdr->MessageLength >= serializer->svc_header_size) {

		*resp_len = hdr->MessageLength - serializer->svc_header_size;
		*resp_buf = &hdr->Data[serializer->svc_header_size];

		/* Deserialize the service specific header */
		serializer->header_decode(serializer, hdr->Data, efi_status);
	}
}

static void smm_variable_header_encode(
	const struct mm_communicate_serializer *serializer,
	uint8_t *buf,
	uint32_t opcode)
{
	SMM_VARIABLE_COMMUNICATE_HEADER *hdr = (SMM_VARIABLE_COMMUNICATE_HEADER*)buf;
	hdr->Function = opcode;
	hdr->ReturnStatus = EFI_SUCCESS;
}

static void smm_variable_header_decode(
	const struct mm_communicate_serializer *serializer,
	uint8_t *buf,
	efi_status_t *efi_status)
{
	SMM_VARIABLE_COMMUNICATE_HEADER *hdr = (SMM_VARIABLE_COMMUNICATE_HEADER*)buf;
	*efi_status = hdr->ReturnStatus;
}
