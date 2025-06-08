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

	//get_args(argc, argv, &key_size, &inbuf, &inbuf_len);

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_APPLICATION, NULL,
			       NULL, &err_origin);
	
				   
	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT, &op, &err_origin);
	//foo

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
	   
}
