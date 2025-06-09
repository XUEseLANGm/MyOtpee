// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <inttypes.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <acipher_ta.h>
#define TEE_TYPE_INVALID 0x00000000
#define MAX_KEYS 16

struct acipher {
	TEE_ObjectHandle key;
	TEE_ObjectHandle db_handle;    
    struct persistent_key_db *db_header; 
};

struct key_store {
    const char *alias;  // 逻辑名称
    uint32_t storage_id;   // 物理存储ID
    uint32_t key_type;
	uint32_t key_size;
};

struct persistent_key_db {
    uint32_t key_count;                   // 当前密钥数量
    struct key_store entries[MAX_KEYS];   // 密钥条目
};

static uint32_t convert_key_type(uint32_t user_type) {
    switch(user_type) {
        case 1: return TEE_TYPE_RSA_KEYPAIR;   
        case 2: return TEE_TYPE_DSA_KEYPAIR;       
        case 3: return TEE_TYPE_DH_KEYPAIR; 
		case 4: return TEE_TYPE_ECDSA_KEYPAIR;
		case 5: return TEE_TYPE_ECDH_KEYPAIR;
		case 6: return TEE_TYPE_SM2_DSA_KEYPAIR;
		case 7: return TEE_TYPE_SM2_KEP_KEYPAIR;
		case 8: return TEE_TYPE_SM2_PKE_KEYPAIR;
        default: return TEE_TYPE_INVALID;
    }
}

void generate_random_suffix(char *buf, size_t len) {
	uint8_t random_bytes[8]; 
    TEE_GenerateRandom(random_bytes, sizeof(random_bytes));
    
    for (size_t i = 0; i < sizeof(random_bytes) && (2*i + 1) < len; i++) {
        snprintf(buf + 2*i, 3, "%02x", random_bytes[i]);
    }
	buf[len - 1] = '\0';
}
TEE_Result add_key_to_db(struct acipher *state, const char *alias, uint32_t storage_id, 
                         uint32_t key_type, uint32_t key_size) {
	if (state->db_header->key_count >= MAX_KEYS) {
		return TEE_ERROR_OVERFLOW;
	}

    state->db_header->entries[state->db_header->key_count] = (struct key_store){
        .alias = alias,
        .storage_id = storage_id,
        .key_type = key_type,
        .key_size = key_size
    };
    state->db_header->key_count++;

    return TEE_SUCCESS;
}
static TEE_Result cmd_gen_key(struct acipher *state, uint32_t pt,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint32_t key_size;
	TEE_ObjectHandle key;
	const uint32_t key_type = convert_key_type(params[0].value.a);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;


	key_size = 1024;

	res = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
		return res;
	}

	res = TEE_GenerateKey(key, key_size, NULL, 0);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32,
		     key_size, res);
		TEE_FreeTransientObject(key);
		return res;
	}else{
		DMSG("Key generated successfully");
	}

	TEE_ObjectInfo key_info;
    TEE_GetObjectInfo(key, &key_info);

    // 3. 持久化密钥
    TEE_ObjectHandle persistent_key;
	char alias[20],rand[16];
	generate_random_suffix(rand, sizeof(rand));
	snprintf(alias, sizeof(alias), "%x_%s",params[0].value.a,rand);
	uint32_t storage_id = TEE_STORAGE_PRIVATE; 
    res = add_key_to_db(state, alias, TEE_STORAGE_PRIVATE, key_info.objectType, key_size);
	DMSG("break point 1");
    if (res == TEE_SUCCESS) {
		// 密钥信息存储到db成功，创建持久化存储对象
        res = TEE_CreatePersistentObject(
				storage_id,
				alias, strlen(alias),
				TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE,
				NULL,
				&key_info,
				sizeof(key_info),
				&persistent_key
    	);
		DMSG("break point 1.5");
		if (res != TEE_SUCCESS) {
			EMSG("Failed to persist key: 0x%x", res);
			TEE_CloseObject(persistent_key);
			// 如果持久化失败，删除临时密钥对象
			state->db_header->key_count--;
			return res;
    	}
		TEE_FreeTransientObject(key);
    }else{
		//如果密钥信息存储到db失败，返回失败结果
		return res;
	}
	DMSG("break point 2");
	TEE_FreeTransientObject(state->key);
	state->key = persistent_key;
	return TEE_SUCCESS;
}


TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	DMSG("has been called");
	return TEE_SUCCESS;

}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
					TEE_Param __unused params[4],
					void **session)
{
	DMSG("has been called");
	struct acipher *state;
	/*
	 * Allocate and init state for the session.
	 */
	state = TEE_Malloc(sizeof(*state), 0);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->key = TEE_HANDLE_NULL;
	*session = state;
	
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	DMSG("has been called");
	struct acipher *state = session;

	
	TEE_Result res = TEE_WriteObjectData(state->db_handle, state->db_header, 
								sizeof(struct persistent_key_db));
	DMSG("break point 3");
	if (res != TEE_SUCCESS) {
		DMSG("break point 3.5");
		EMSG("Failed to init DB: %#" PRIx32, res);
		TEE_Free(state->db_header);
		TEE_CloseAndDeletePersistentObject(state->db_handle);
		TEE_Free(state);
	}
	DMSG("break point 4");
	
	// TEE_FreeTransientObject(state->key);
	// TEE_Free(state);
	
	DMSG("break point 5");
}

TEE_Result open_database(void *session){

	struct acipher *state = session;

	// 尝试打开存储密钥ID的数据库
	TEE_ObjectHandle persistent_db_obj = NULL;
	struct persistent_key_db *db_data = NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | 
                TEE_DATA_FLAG_ACCESS_WRITE_META;
	uint32_t count = 0;
	// 尝试打开现有的持久化存储对象
	TEE_Result res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                        "keydatabase", sizeof("keydatabase"),
                                        flags, &persistent_db_obj);

	
	if (res == TEE_SUCCESS) {
		DMSG("Found existing key database");
		// 读取数据库头信息（不加载全部密钥，按需加载）
		db_data = TEE_Malloc(sizeof(struct persistent_key_db), TEE_MALLOC_FILL_ZERO);
		if (!db_data) {
			TEE_CloseObject(persistent_db_obj);
			TEE_Free(state);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
		
		res = TEE_ReadObjectData(persistent_db_obj, db_data, 
							sizeof(struct persistent_key_db),&count);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to read DB header: %#" PRIx32, res);
			TEE_Free(db_data);
			TEE_CloseObject(persistent_db_obj);
			TEE_Free(state);
			return res;
		}

		state->db_handle = persistent_db_obj;
		state->db_header = db_data;
	} else if (res ==TEE_ERROR_ITEM_NOT_FOUND) {
		DMSG("Creating new key database");
		
		// 创建新的空数据库
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
									"keydatabase", sizeof("keydatabase"),
									flags, TEE_HANDLE_NULL, NULL, 0,
									&persistent_db_obj);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create key database: %#" PRIx32, res);
			TEE_Free(state);
			return res;
		}
		
		// 初始化数据库结构
		db_data = TEE_Malloc(sizeof(struct persistent_key_db), TEE_MALLOC_FILL_ZERO);
		if (!db_data) {
			TEE_CloseAndDeletePersistentObject(persistent_db_obj);
			TEE_Free(state);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
		
		TEE_MemFill(db_data, 0, sizeof(struct persistent_key_db));
		db_data->key_count = 0;
		
		// 写回空数据库
		res = TEE_WriteObjectData(persistent_db_obj, db_data, 
								sizeof(struct persistent_key_db));
		if (res != TEE_SUCCESS) {
			EMSG("Failed to init DB: %#" PRIx32, res);
			TEE_Free(db_data);
			TEE_CloseAndDeletePersistentObject(persistent_db_obj);
			TEE_Free(state);
			return res;
		}else{
			DMSG("New key database created successfully");
		}
		 
		state->db_handle = persistent_db_obj;
		state->db_header = db_data;
	} else {
		EMSG("Unexpected DB error: %#" PRIx32, res);
		TEE_Free(state);
		return res;
	}
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	open_database(session);
	// struct acipher *state = session;
	switch (cmd) {
		case TA_ACIPHER_CMD_GEN_KEY:
			return cmd_gen_key(session, param_types, params);
		default:
			EMSG("Unknown command 0x%" PRIx32, cmd);
			return TEE_ERROR_BAD_PARAMETERS;
	}

}


