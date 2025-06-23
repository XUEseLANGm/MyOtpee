/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COMMON_EFI_CERTIFICATE_H
#define COMMON_EFI_CERTIFICATE_H

#include <stdint.h>
#include "efi_types.h"

/* Certificate types (wCertificateType) */
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define WIN_CERT_TYPE_EFI_PKCS115      0x0EF0
#define WIN_CERT_TYPE_EFI_GUID         0x0EF1

/* Current WIN_CERTIFICATE version */
#define WIN_CERT_CURRENT_VERSION	   0x0200

/**
 * The Authenticode WIN_CERTIFICATE structure
 */
typedef struct {

	/* Length of certificate plus header in bytes */
	uint32_t  dwLength;

	/* The revision of this structure */
	uint16_t  wRevision;

	/* Certificate type */
	uint16_t  wCertificateType;

	/* Certificate bytes follow this structure */

} WIN_CERTIFICATE;

/**
 * Extends WIN_CERTIFICATE for a GUID defined certificate type
 * (wCertificateType in WIN_CERTIFICATE set to WIN_CERT_TYPE_EFI_GUID).
 */
typedef struct {

	WIN_CERTIFICATE  Hdr;
	EFI_GUID         CertType;
	uint8_t          CertData[1];

} WIN_CERTIFICATE_UEFI_GUID;


#endif /* COMMON_EFI_CERTIFICATE_H */
