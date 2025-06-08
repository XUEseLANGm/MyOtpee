/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <hello_world_ta.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <hello_world_ta.h>

// 持久化对象标识符
TEE_ObjectHandle obj = TEE_HANDLE_NULL;
const char *objectID = "001";
size_t objectIDLen = 4;
TEE_Result res;

static uint32_t get_counter(uint32_t counter)
{
    TEE_ObjectHandle obj;
    TEE_Result res;
    // uint32_t counter = 0;
    size_t len;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   objectID, objectIDLen,
                                   TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
                                   &obj);


    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        // 如果对象不存在，创建一个新的
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                         objectID, objectIDLen,
                                         TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
                                         TEE_HANDLE_NULL, &counter, sizeof(counter), &obj);

        if (res != TEE_SUCCESS) {
            DMSG("Failed to create persistent object: 0x%x", res);
            return 0;
        }
    } else if (res != TEE_SUCCESS) {
        DMSG("Failed to open persistent object: 0x%x", res);
        return 0;
    }

    // 从对象中读取计数值
    len = sizeof(counter);
    res = TEE_ReadObjectData(obj, &counter, sizeof(counter), &len);
    if (res != TEE_SUCCESS || len != sizeof(counter)) {
        DMSG("Failed to read object data: 0x%x / %u", res, len);
        TEE_CloseObject(obj);
        return 0;
    }

    TEE_CloseObject(obj);
    return counter;
}

static void set_counter(uint32_t value)
{
    TEE_ObjectHandle obj;
    TEE_Result res;

    // 打开已存在的对象
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                   objectID, objectIDLen,
                                   TEE_DATA_FLAG_ACCESS_WRITE,
                                   &obj);
    if (res != TEE_SUCCESS) {
        DMSG("Failed to open object for writing: 0x%x", res);
        return;
    }

    // 定位到文件头
    TEE_SeekObjectData(obj, 0, TEE_DATA_SEEK_SET);

    // 写入数据
    res = TEE_WriteObjectData(obj, &value, sizeof(value));
    if (res != TEE_SUCCESS) {
        DMSG("Failed to write object data: 0x%x", res);
    }

    TEE_CloseObject(obj);
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result inc_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t counter = get_counter(params[0].value.a);

	IMSG("Got value: %u from NW", counter);
	params[0].value.a = ++counter;
	IMSG("Increase value to: %u", counter);

	set_counter(counter);
	IMSG("Counter value saved to persistent storage");

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_HELLO_WORLD_CMD_INC_VALUE:
		return inc_value(param_types, params);
	case TA_HELLO_WORLD_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
