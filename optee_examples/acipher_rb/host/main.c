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

int main(int argc, char *argv[])
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	size_t key_size;
	void *inbuf;
	size_t inbuf_len;
	size_t n;
	const TEEC_UUID uuid = TA_ACIPHER_UUID;

	// Check input parameters
	if (argc < 2) {
		errx(1, "Usage: %s <action> <args...>\n"
			"Actions:\n"
			" data_enc <input_file> <output_file>\n"
			" data_dec <input_file> <output_file>\n"
			" data_read <key_id>\n"
			" data_del <key_id>\n"
			" key_gen <key_id> <key_type> <key_size>\n"
			" key_import <key_id> <key_file>\n"
			" key_export <key_id> <key_file>", argv[0]);
	}

	char *action = argv[1];
	char *sub_action = argv[2];

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_APPLICATION, NULL,
			       NULL, &err_origin);
	

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
		if (argc != 2) {
			errx(1, "Usage: %s key_gen", argv[0]);
		}

		res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_GEN_KEY, &op, &err_origin);

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
