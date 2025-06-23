/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_SMM_VARIABLE_PARAMETERS_H
#define TS_SMM_VARIABLE_PARAMETERS_H

#include <stddef.h>

#include "protocols/common/efi/efi_status.h"
#include "protocols/common/efi/efi_types.h"
#include "protocols/common/efi/efi_certificate.h"
#include <protocols/common/efi/efi_global_variable.h>
#include <protocols/common/efi/efi_image_authentication.h>

/**
 * C/C++ definition of smm_variable service parameters
 *
 * These defines are aligned to the SMM Variable definitions from EDK2. These versions
 * of these defines are maintained in the TS project to avoid a mandatory dependency
 * on the EDK2 project.
 */

/**
 * SMM variable call header
 */
typedef struct {
	uint64_t Function;
	efi_status_t ReturnStatus;
	uint8_t Data[1];
} SMM_VARIABLE_COMMUNICATE_HEADER;

#define SMM_VARIABLE_COMMUNICATE_HEADER_SIZE \
	offsetof(SMM_VARIABLE_COMMUNICATE_HEADER, Data)

/**
 * Variable attributes
 */
#define	EFI_VARIABLE_NON_VOLATILE				(0x00000001)
#define	EFI_VARIABLE_BOOTSERVICE_ACCESS				(0x00000002)
#define	EFI_VARIABLE_RUNTIME_ACCESS				(0x00000004)
#define	EFI_VARIABLE_HARDWARE_ERROR_RECORD			(0x00000008)
#define	EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS			(0x00000010)
#define	EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS	(0x00000020)
#define	EFI_VARIABLE_APPEND_WRITE				(0x00000040)
#define EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS              (0x00000080)

#define	EFI_VARIABLE_MASK \
	(EFI_VARIABLE_NON_VOLATILE | \
	 EFI_VARIABLE_BOOTSERVICE_ACCESS | \
	 EFI_VARIABLE_RUNTIME_ACCESS | \
	 EFI_VARIABLE_HARDWARE_ERROR_RECORD | \
	 EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | \
	 EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | \
	 EFI_VARIABLE_APPEND_WRITE | \
	 EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS)

/**
 * Parameter structure for SetVariable and GetVariable.
 */
typedef struct {
	EFI_GUID		Guid;
	uint64_t		DataSize;
	uint64_t		NameSize;
	uint32_t		Attributes;
	int16_t			Name[1];
} SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE;

#define SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_NAME_OFFSET \
	offsetof(SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name)

#define SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_DATA_OFFSET(s) \
	(offsetof(SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name) + s->NameSize)

#define SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_TOTAL_SIZE(s) \
	(offsetof(SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name) + s->NameSize + s->DataSize)

#define SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE_SIZE(name_size, data_size) \
	(offsetof(SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name) + name_size + data_size)

/**
 * Parameter structure for GetNextVariableName.
 */
typedef struct {
	EFI_GUID		Guid;
	uint64_t		NameSize;
	int16_t			Name[1];
} SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME;

#define SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME_NAME_OFFSET \
	offsetof(SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name)

#define SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME_TOTAL_SIZE(s) \
	(offsetof(SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name) + s->NameSize)

#define SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME_SIZE(name_size) \
	(offsetof(SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name) + name_size)

/**
 * Parameter structure for QueryVariableInfo.
 */
typedef struct {
	uint64_t		MaximumVariableStorageSize;
	uint64_t		RemainingVariableStorageSize;
	uint64_t		MaximumVariableSize;
	uint32_t		Attributes;
} SMM_VARIABLE_COMMUNICATE_QUERY_VARIABLE_INFO;

/**
 * Variable check property structure. Specifies check constraints
 * for a variable.
 */
typedef struct {
	uint16_t		Revision;
	uint16_t		Property;
	uint32_t		Attributes;
	uint64_t		MinSize;
	uint64_t		MaxSize;
} VAR_CHECK_VARIABLE_PROPERTY;

#define VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY     	(1U << 0)

/* Supported check property revision */
#define VAR_CHECK_VARIABLE_PROPERTY_REVISION		(0x0001)

/**
 * Parameter structure for VarCheckVariableProperty Set/Get
 */
typedef struct {
	EFI_GUID					Guid;
	uint64_t					NameSize;
	VAR_CHECK_VARIABLE_PROPERTY	VariableProperty;
	int16_t						Name[1];
} SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY;

#define SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY_NAME_OFFSET \
	offsetof(SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name)

#define SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY_TOTAL_SIZE(s) \
	(offsetof(SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name) + s->NameSize)

#define SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY_SIZE(name_size) \
	(offsetof(SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name) + name_size)

/**
 * Parameter structure for GetPayloadSize.
 */
typedef struct {
	uint64_t						VariablePayloadSize;
} SMM_VARIABLE_COMMUNICATE_GET_PAYLOAD_SIZE;

/**
 * Authentication header included at the start of variable data for SetVariable operations
 * when the EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute is set.
 */
typedef struct {
	EFI_TIME                    TimeStamp;
	WIN_CERTIFICATE_UEFI_GUID   AuthInfo;
} EFI_VARIABLE_AUTHENTICATION_2;

#define EFI_VARIABLE_AUTHENTICATION_2_SIZE_WITHOUT_CERTDATA \
	offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo.CertData)

#endif /* TS_SMM_VARIABLE_PARAMETERS_H */
