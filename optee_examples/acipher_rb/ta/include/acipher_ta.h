// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __ACIPHER_TA_H__
#define __ACIPHER_TA_H__

/* UUID of the acipher example trusted application */
#define TA_ACIPHER_UUID \
	   { 0xc0557986, 0x90f1, 0x4c3d, \
                {0x86, 0x40, 0x35, 0x47, 0x73, 0xf5, 0xf3, 0x68 } }

/*
 * in	params[0].value.a key size
 */
#define TA_ACIPHER_CMD_GEN_KEY		0

/*
 * in	params[1].memref  input
 * out	params[2].memref  output
 */
#define TA_ACIPHER_CMD_IMPORT_KEY		1

#define TA_ACIPHER_CMD_EXPORT_KEY		2

#define TA_ACIPHER_CMD_ENCRYPT		3

#define TA_ACIPHER_CMD_DECRYPT		4

#define TA_ACIPHER_CMD_READ_DATA		5

#define TA_ACIPHER_CMD_DELETE_DATA		6

#endif /* __ACIPHER_TA_H */
