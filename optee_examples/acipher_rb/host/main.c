// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <acipher_ta.h>

// rb_acipher data_enc\dec\read\del key_gen\import\export
static void CA_Showkeys(struct key_db *key_datebase){
	if (key_datebase == NULL) {
		printf("Receive Key database failed.\n");
		return ;
	}

	printf("Current key count: %u\n", key_datebase->key_count);
	for (uint32_t i = 0; i < key_datebase->key_count; i++) {
		printf("alias: %s ", key_datebase->keys[i].alias);
		printf("key_type: %x ", key_datebase->keys[i].key_type);
		printf("key_size: %x\n", key_datebase->keys[i].key_size);
	}
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	struct key_db key_datebase;
	TEEC_SharedMemory shm;
	const TEEC_UUID uuid = TA_ACIPHER_UUID;

	// Check input parameters
	if (argc < 2) {
		errx(1, "Usage: %s <action> <args...>\n"
			"Actions:\n"
			" data_enc <input_file> <output_file>\n"
			" data_dec <input_file> <output_file>\n"
			" data_read <key_id>\n"
			" data_del <key_id>\n"
			" key_gen <key_type> <key_size>\n"
			" key_list \n"
			" key_import <key_id> <key_file>\n"
			" key_export <key_id> <key_file>", argv[0]);
	}

	char *action = argv[1];
	char *sub_action = argv[2];

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

	// Validate sub-actions and their arguments
	if (strcmp(action, "data_enc") == 0 || strcmp(action, "data_dec") == 0) {
		if (argc != 5) {
			errx(1, "Usage: %s rb_acipher %s <input_file> <output_file>", argv[0], action);
		}
	} else if (strcmp(action, "data_read") == 0 || strcmp(action, "data_del") == 0) {
		if (argc != 4) {
			errx(1, "Usage: %s rb_acipher %s <key_id>", argv[0], action);
		}
	} else if (strcmp(action, "key_gen") == 0) {
		if (argc != 3) {
			errx(1, "Usage: %s key_gen <key_type>", argv[0]);
		}
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
							TEEC_NONE,
							TEEC_NONE,
							TEEC_NONE);
		op.params[0].value.a = strtoul(sub_action, NULL, 10);
		res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_GEN_KEY, &op, &err_origin);

	} else if (strcmp(action, "key_list") == 0) {
		if (argc != 2) {
			errx(1, "Usage: key_list");
		}

		// Register shared memory for reading key_db
    	shm.size = sizeof(struct key_db); 
		printf("shm.size = %zu\n", shm.size);
		shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;  // CA和TA均可读写
		
		res = TEEC_AllocateSharedMemory(&ctx, &shm);
		if (res != TEEC_SUCCESS) {
			printf("TEEC_RegisterSharedMemory failed: 0x%x\n", res);
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			return 1;
		}
		
		// 定义TEEC_Operation参数
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT,
							TEEC_NONE,
							TEEC_NONE,
							TEEC_NONE);
	
		op.params[0].memref.parent = &shm;
		op.params[0].memref.size = shm.size;
		op.params[0].memref.offset = 0;  
		res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_LIST_KEY, &op, &err_origin);
		if( res != TEEC_SUCCESS) {
			errx(1, "TEEC_InvokeCommand(TA_ACIPHER_CMD_LIST_KEY): %#" PRIx32, res);
		}

		// 显示key_db内容
		CA_Showkeys((struct key_db *)shm.buffer);

		// 释放共享内存
		TEEC_ReleaseSharedMemory(&shm);

	} else if (strcmp(action, "key_import") == 0 || strcmp(action, "key_export") == 0) {
		if (argc != 5) {
			errx(1, "Usage: %s rb_acipher %s <key_id> <key_file>", argv[0], action);
		}
	} else {
		errx(1, "Invalid sub-action: %s\n"
			"Valid sub-actions: data_enc, data_dec, data_read, data_del, key_gen, key_import, key_export", 
			action);
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
	   
}
