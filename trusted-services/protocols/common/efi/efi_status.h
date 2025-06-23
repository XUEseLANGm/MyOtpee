/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COMMON_EFI_STATUS_H
#define COMMON_EFI_STATUS_H

#include <limits.h>
#include <stdint.h>

/**
 * Common EFI status type
 */
typedef uint64_t efi_status_t;

/* For error class status codes */
#define EFI_ERROR(s)	((1ULL << ((CHAR_BIT * sizeof(efi_status_t)) - 1)) | s)

/**
 * Common EFI status codes
 */
#define EFI_SUCCESS					0x0
#define EFI_LOAD_ERROR				EFI_ERROR(0x01)
#define EFI_INVALID_PARAMETER		EFI_ERROR(0x02)
#define EFI_UNSUPPORTED				EFI_ERROR(0x03)
#define EFI_BAD_BUFFER_SIZE			EFI_ERROR(0x04)
#define EFI_BUFFER_TOO_SMALL		EFI_ERROR(0x05)
#define EFI_NOT_READY				EFI_ERROR(0x06)
#define EFI_DEVICE_ERROR			EFI_ERROR(0x07)
#define EFI_WRITE_PROTECTED			EFI_ERROR(0x08)
#define EFI_OUT_OF_RESOURCES		EFI_ERROR(0x09)
#define EFI_VOLUME_CORRUPTED		EFI_ERROR(0x0a)
#define EFI_VOLUME_FULL				EFI_ERROR(0x0b)
#define EFI_NO_MEDIA				EFI_ERROR(0x0c)
#define EFI_MEDIA_CHANGED			EFI_ERROR(0x0d)
#define EFI_NOT_FOUND				EFI_ERROR(0x0e)
#define EFI_ACCESS_DENIED			EFI_ERROR(0x0f)
#define EFI_NO_RESPONSE				EFI_ERROR(0x10)
#define EFI_NO_MAPPING				EFI_ERROR(0x11)
#define EFI_TIMEOUT					EFI_ERROR(0x12)
#define EFI_NOT_STARTED				EFI_ERROR(0x13)
#define EFI_ALREADY_STARTED			EFI_ERROR(0x14)
#define EFI_ABORTED					EFI_ERROR(0x15)
#define EFI_ICMP_ERROR				EFI_ERROR(0x16)
#define EFI_TFTP_ERROR				EFI_ERROR(0x17)
#define EFI_PROTOCOL_ERROR			EFI_ERROR(0x18)
#define EFI_INCOMPATIBLE_VERSION	EFI_ERROR(0x19)
#define EFI_SECURITY_VIOLATION		EFI_ERROR(0x1a)
#define EFI_CRC_ERROR				EFI_ERROR(0x1b)
#define EFI_END_OF_MEDIA			EFI_ERROR(0x1c)
#define EFI_END_OF_FILE				EFI_ERROR(0x1f)
#define EFI_INVALID_LANGUAGE		EFI_ERROR(0x20)
#define EFI_COMPROMISED_DATA		EFI_ERROR(0x21)
#define EFI_HTTP_ERROR				EFI_ERROR(0x23)


#endif /* COMMON_EFI_STATUS_H */
