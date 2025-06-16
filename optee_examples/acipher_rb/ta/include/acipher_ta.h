// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
// #include <inttypes.h>
// #include <string.h>
// #include <tee_internal_api.h>
// #include <tee_internal_api_extensions.h>

#ifndef __ACIPHER_TA_H__
#define __ACIPHER_TA_H__

#define TEE_TYPE_INVALID 0x00000000
#define MAX_ALIAS_LENGTH 20
#define MAX_KEYS 16

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

// uint32_t TA_Convert_Key_Type(uint32_t user_type);

// void TA_Generate_Random(char *buf, size_t len);

// TEE_Result TA_Add_Key2db(struct key_info *keyinfo, char alias[MAX_ALIAS_LENGTH], uint32_t storage_id, uint32_t key_type, uint32_t key_size);

// TEE_Result TA_Gen_Key(struct acipher *state, uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

// TEE_Result TA_Open_Database(void *session);

// TEE_Result TA_Read_Persistent_Object(const char *alias, void **out_data, size_t *out_size);

// void TA_Showkeys(void);


                