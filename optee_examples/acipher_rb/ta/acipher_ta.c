// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <inttypes.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <acipher_ta.h>


struct acipher {
	TEE_ObjectHandle key;
};

TEE_ObjectHandle key_db_obj = NULL;
struct key_db *key_datebase = NULL;
// struct key_info keyinfo[MAX_KEYS];

static uint32_t TA_Convert_Key_Type(uint32_t user_type) {
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

static TEE_Result TA_Add_Key2db(struct key_info *keyinfo, char alias[MAX_ALIAS_LENGTH], uint32_t storage_id, 
                         uint32_t key_type, uint32_t key_size) {
	
	// 检查数据库是否为空
	if (key_datebase == NULL) {
        return TEE_ERROR_BAD_STATE;
    }

	// 检查数据库容量
	if (key_datebase->key_count >= MAX_KEYS) {
		return TEE_ERROR_OVERFLOW;
	}

	// 检查是否已存在相同别名的密钥
	for (uint32_t i = 0; i < key_datebase->key_count; i++) {
        if (strncmp(key_datebase->keys[i].alias, alias, strlen(alias)) == 0) {
            return TEE_ERROR_ACCESS_CONFLICT;
        }
    }

	strncpy(keyinfo->alias, alias, MAX_ALIAS_LENGTH - 1);
    keyinfo->alias[MAX_ALIAS_LENGTH - 1] = '\0'; 

	keyinfo->storage_id = storage_id;
	keyinfo->key_type = key_type;
	keyinfo->key_size = key_size;

	key_datebase->key_count++;

	// for (uint32_t i = 0; i < key_datebase->key_count; i++) {
	// 	printf("%x : %s\n",i, key_datebase->keys[i].alias);
    // }

    return TEE_SUCCESS;
}

// static TEE_Result TA_DecryptTest(void *alias){
// 	// foo 位置插入的 RSA 专用测试代码
//     DMSG("--- Starting RSA encryption test with persistent key ---");
    
//     // 1. 准备测试数据 (RSA加密有长度限制，需要分段处理)
//     const char *plaintext = "OP-TEE RSA test";
//     size_t plaintext_len = strlen(plaintext) + 1; // 包含NULL终止符
//     uint8_t *ciphertext = NULL;
//     uint8_t *decrypted = NULL;
//     size_t ciphertext_len = 0;
//     size_t decrypted_len = 0;
// 	uint32_t storage_id = TEE_STORAGE_PRIVATE; 
//     // TEE_Result res = TEE_SUCCESS;

//     // 2. 通过alias重新打开持久化RSA密钥对象
//     TEE_ObjectHandle rsa_key = TEE_HANDLE_NULL;
//     TEE_Result res = TEE_OpenPersistentObject(
//             storage_id,
//             alias, strlen(alias),
//             TEE_DATA_FLAG_ACCESS_READ,
//             &rsa_key);
    
//     if (res != TEE_SUCCESS) {
//         EMSG("Failed to open RSA key: 0x%x", res);
//         // goto cleanup;
//     }

//     TEE_OperationHandle oper = TEE_HANDLE_NULL;
// 	res = TEE_AllocateOperation(&oper, 
// 						TEE_ALG_RSAES_PKCS1_V1_5, 
// 						TEE_MODE_ENCRYPT,
// 						1024); // 与模数位数一致
// 	if (res != TEE_SUCCESS) {
// 		EMSG("Allocate operation failed: 0x%x", res);
// 	}

// 	// 设置公钥参数
// 	res = TEE_SetOperationKey(oper, rsa_key);
// 	if (res != TEE_SUCCESS) {
// 		TEE_FreeOperation(oper);
// 		return res;
// 	}

// 		DMSG("DEBUG -1");

// 	DMSG("DEBUG 1");
// 	res = TEE_AsymmetricEncrypt(oper,
// 							NULL, 0, // 无额外参数
// 							plaintext, plaintext_len,
// 							NULL, &ciphertext_len); // mod_len复用为输出长度

// 	ciphertext = TEE_Malloc(ciphertext_len, 0);
						
// 	res = TEE_AsymmetricEncrypt(oper,
// 							NULL, 0, // 无额外参数
// 							plaintext, plaintext_len,
// 							ciphertext, &ciphertext_len); // mod_len复用为输出长度
							
// 	if (res != TEE_SUCCESS) {
// 		EMSG("Asymmetric encrypt failed: 0x%x", res);
// 	}

// 	printf("ciphertext:\n"); 
// 	for (size_t i = 0; i < ciphertext_len; i++) {
//         printf("%02x ", ciphertext[i]); // 16进制格式
//         if ((i + 1) % 8 == 0) printf("\n");
//     }
// 	printf("\n");
// 	res = TEE_AllocateOperation(&oper, 
// 						TEE_ALG_RSAES_PKCS1_V1_5, 
// 						TEE_MODE_DECRYPT,
// 						1024); // 与模数位数一致
// 	if (res != TEE_SUCCESS) {
// 		EMSG("Allocate operation failed: 0x%x", res);
// 	}

// 	// 设置公钥参数
// 	res = TEE_SetOperationKey(oper, rsa_key);
// 	if (res != TEE_SUCCESS) {
// 		TEE_FreeOperation(oper);
// 		return res;
// 	}

// 	res = TEE_AsymmetricDecrypt(oper,
// 							NULL, 0, // 无额外参数
// 							ciphertext, ciphertext_len,
// 							NULL, &decrypted_len); // mod_len复用为输出长度

// 	decrypted = TEE_Malloc(decrypted_len, 0);
// 	res = TEE_AsymmetricDecrypt(oper,
// 							NULL, 0, // 无额外参数
// 							ciphertext, ciphertext_len,
// 							decrypted, &decrypted_len); // mod_len复用为输出长度
	
// 	printf("decrypted:\n"); 
// 	for (size_t i = 0; i < decrypted_len; i++) {
//         printf("%02x ", decrypted[i]); // 16进制格式
//         if ((i + 1) % 8 == 0) printf("\n");
//     }
// 	printf("\n");
// 	printf("%s\n", (char *)decrypted);
// 	TEE_CloseObject(rsa_key);

// 	DMSG("--- Finished RSA encryption test with persistent key ---");
// }

static TEE_Result TA_Gen_Key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_ObjectHandle key;
	const uint32_t  expected_param_types = TEE_PARAM_TYPES( \
											TEE_PARAM_TYPE_VALUE_INPUT, \
											TEE_PARAM_TYPE_MEMREF_INPUT, \
											TEE_PARAM_TYPE_NONE, \
											TEE_PARAM_TYPE_NONE);
	if (param_types != expected_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// 获取密钥类型
	uint32_t raw_key_type = params[0].value.a;  //原始key_type
	const uint32_t key_type = TA_Convert_Key_Type(raw_key_type);
	uint32_t key_size = 1024; // 密钥大小，暂时指定为特定值
	
	// 获取密钥名称
	size_t key_name_len = params[1].memref.size;
	void *alias = TEE_Malloc(key_name_len, TEE_MALLOC_FILL_ZERO);
	memcpy(alias, params[1].memref.buffer, key_name_len);
	// 确保字符串格式的名称以'\0'结尾
	((char *)alias)[key_name_len] = '\0';
		
	TEE_ObjectHandle persistent_key;
	uint32_t storage_id = TEE_STORAGE_PRIVATE; 

	// 分配临时密钥对象
	res = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
		return res;
	}

	// 将生成的密钥存储到临时密钥对象中
	res = TEE_GenerateKey(key, key_size, NULL, 0);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, key_size, res);
		goto error;
	}

	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META |
					    TEE_DATA_FLAG_OVERWRITE;

	res = TA_Add_Key2db(&(key_datebase->keys[key_datebase->key_count]), alias, storage_id, key_type, key_size);
	if (res == TEE_SUCCESS) {
		// 密钥信息成功存储到datebase，创建持久化存储对象
        res = TEE_CreatePersistentObject(
				storage_id,
				alias, strlen(alias),
				flags,key,NULL,0,
				&persistent_key
    	);
		DMSG("RES of TEE_CreatePersistentObject for persistent_key : %#x", res);
		if (res != TEE_SUCCESS) {
			// 如果持久化失败，删除临时密钥对象
			EMSG("Failed to create persist key: 0x%x", res);
			key_datebase->key_count--;
			goto error;
    	}
		
		TEE_CloseObject(persistent_key);
		
		TEE_FreeTransientObject(key);
    }else{
		//密钥信息存储到datebase失败，返回失败结果
		EMSG("Failed to add key to database: 0x%x", res);
		goto error;
	}
	
	TEE_SeekObjectData(key_db_obj, 0, TEE_DATA_SEEK_SET);
	res = TEE_WriteObjectData(key_db_obj, key_datebase, sizeof(struct key_db));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to Write DB: %#" PRIx32, res);
		goto error;
	}
	
	// TA_DecryptTest(alias); 调用测试函数，进行加密解密测试
	return TEE_SUCCESS;

error:
	// 如果发生错误，释放资源并返回错误码
	if (key) {
		TEE_FreeTransientObject(key);
	}
	if (persistent_key != TEE_HANDLE_NULL) {
		TEE_CloseAndDeletePersistentObject(persistent_key);
	}
	return res;
}

static TEE_Result TA_Open_Database(void *session){

	struct acipher *state = session;

	// 尝试打开存储密钥的数据库
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META;

	TEE_Result res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                        "keydatabase", sizeof("keydatabase"),
                                        flags, &key_db_obj);

	// 如果找到密钥数据库，则打开该数据库
	if (res == TEE_SUCCESS) {
		DMSG("Found existing key database");
		size_t read_count = 0;
		key_datebase = TEE_Malloc(sizeof(struct key_db), TEE_MALLOC_FILL_ZERO);
		if (!key_datebase) {
			// 返回内存不足错误码
			res = TEE_ERROR_OUT_OF_MEMORY;
            goto error;
		}
		
		// 将句柄中存储的数据保存到key_datebase中
		res = TEE_ReadObjectData(key_db_obj, key_datebase, sizeof(struct key_db),&read_count);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to read DB Handle: %#" PRIx32, res);
			goto error;
		}
	// 如果未找到密钥数据库，则创建数据库
	} else if (res ==TEE_ERROR_ITEM_NOT_FOUND) {
		DMSG("Creating new key database");
		
		// 创建新的空数据库
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
									"keydatabase", sizeof("keydatabase"),
									flags, TEE_HANDLE_NULL, NULL, 0,
									&key_db_obj);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create key database: %#" PRIx32, res);
			goto error;
		}
		
		// 初始化数据库结构
		key_datebase = TEE_Malloc(sizeof(struct key_db), TEE_MALLOC_FILL_ZERO);
		if (!key_datebase) {
			res = TEE_ERROR_OUT_OF_MEMORY;
            goto error;
		}
		
		key_datebase->key_count = 0;
		
		// 保存密钥数据库信息
		res = TEE_WriteObjectData(key_db_obj, key_datebase, sizeof(struct key_db));
		if (res != TEE_SUCCESS) {
			EMSG("Failed to init DB: %#" PRIx32, res);
			goto error;
		}

	} else {
		EMSG("Unexpected DB error: %#" PRIx32, res);
		goto error;
	}
	return TEE_SUCCESS;

error:
    // 统一错误处理：释放所有资源
    if (key_datebase) {
        TEE_Free(key_datebase);
        key_datebase = NULL;
    }
    if (key_db_obj != TEE_HANDLE_NULL) {
        if (res == TEE_ERROR_ITEM_NOT_FOUND) {
            // 如果是创建失败，删除未完成的数据库
            TEE_CloseAndDeletePersistentObject(key_db_obj);
        } else {
            // 否则仅关闭
            TEE_CloseObject(key_db_obj);
        }
    }
    if (state) {
        TEE_Free(state);
    }
    return res;
}

// static TEE_Result TA_Read_Persistent_Object(const char *alias) {
//     TEE_ObjectHandle object = TEE_HANDLE_NULL;
//     TEE_Result res;
// 	TEE_ObjectInfo info;
    
//     // 打开持久化对象
//     res = TEE_OpenPersistentObject(
//         TEE_STORAGE_PRIVATE,    // 存储区域
//         alias,                  // 对象别名
//         strlen(alias),          // 别名长度
//         TEE_DATA_FLAG_ACCESS_READ,  // 访问权限
//         &object                // 返回的对象句柄
//     );
    
//     if (res != TEE_SUCCESS) {
//         EMSG("Failed to open persistent object: 0x%x", res);
//         return res;
//     }

//     // 获取对象大小
// 	TEE_GetObjectInfo(object, &info);
   
//     TEE_CloseObject(object);
//     return res;
// }
// static void TA_Show_keys(void){
// 	size_t key_size = 0;

// 	DMSG("has been called");
// 	if (key_datebase == NULL) {
// 		EMSG("Key database is not initialized.");
// 		return;
// 	}

// 	DMSG("Current key count: %u", key_datebase->key_count);
// 	for (uint32_t i = 0; i < key_datebase->key_count; i++) {
// 		TA_Read_Persistent_Object(key_datebase->keys[i].alias);
// 		printf("Keysize : %lx\n",key_size);
// 	}
// }

// static void debug_shm_info(void) {
//     uint32_t total_size, free_size;
    
//     TEE_GetPropertyAsU32(TEE_PROPSET_TEE_IMPLEMENTATION,
//                        "gpd.tee.memory.dynshm.size",
//                        &total_size);
    
//     TEE_GetPropertyAsU32(TEE_PROPSET_TEE_IMPLEMENTATION,
//                        "gpd.tee.memory.dynshm.available",
//                        &free_size);
    
//     IMSG("Dynamic Shared Memory: Total=%u bytes (%.1f KB), Free=%u bytes", 
//          total_size, (float)total_size / 1024, free_size);
// }

static int TA_Classify_Key_Type(uint32_t key_type) {
    // 检查是否是对称密钥（0xA0开头且不是非对称公钥）
    if ((key_type & 0xFF000000) == 0xA0000000) {
        // 排除非对称公钥类型
        switch (key_type) {
            case TEE_TYPE_RSA_PUBLIC_KEY:
            case TEE_TYPE_DSA_PUBLIC_KEY:
            case TEE_TYPE_ECDSA_PUBLIC_KEY:
            case TEE_TYPE_ECDH_PUBLIC_KEY:
            case TEE_TYPE_ED25519_PUBLIC_KEY:
            case TEE_TYPE_ED448_PUBLIC_KEY:
            case TEE_TYPE_X25519_PUBLIC_KEY:
            case TEE_TYPE_X448_PUBLIC_KEY:
            case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
            case TEE_TYPE_SM2_KEP_PUBLIC_KEY:
            case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
                break; 
            default:
                return 0; // 对称密钥
        }
    }else if ((key_type & 0xFF000000) == 0xA1000000) {
		// 检查是否是非对称密钥对（0xA1开头）
        return 1; // 非对称密钥对
    }

    // 其他情况
    return -1;
}

static TEE_Result TA_Get_Key(const char *alias, int *key_type_int, TEE_ObjectHandle *key_obj, TEE_ObjectInfo *key_info) {
    // int key_type_int; // 存储密钥类型为对称密钥（0），还是非对称密钥（1）
	TEE_Result res;
	uint32_t key_type; 

    res = TEE_GetObjectInfo1(*key_obj, key_info);
	if(res != TEE_SUCCESS) {
		EMSG("Failed to get key info: alias=%s, res=0x%x", alias, res);
		TEE_CloseObject(*key_obj);
		return res;
	}

    key_type = (*key_info).objectType;
	*key_type_int = TA_Classify_Key_Type(key_type);

    return TEE_SUCCESS;
}

static TEE_Result TA_Dec_Data(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	int key_type;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo key_info;
	if (param_types != TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,  
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE)) 
		return TEE_ERROR_BAD_PARAMETERS;

	// 获取密钥名称
	size_t key_id_len = params[0].memref.size;
	void *key_id = TEE_Malloc(key_id_len, TEE_MALLOC_FILL_ZERO);
	memcpy(key_id, params[0].memref.buffer, key_id_len);
	// 确保字符串格式的名称以'\0'结尾
	((char *)key_id)[key_id_len] = '\0';

	// 获取秘文
	void *input_data= params[1].memref.buffer;
	size_t input_data_len = params[1].memref.size;

	printf("input_data_len : %zu\n", input_data_len);
	printf("Encrypted buffer: \n");
		for (size_t i = 0; i < input_data_len; i++)
			printf("%02x", ((uint8_t *)params[1].memref.buffer)[i]);
		printf("\n");

	
	//定义明文
	void *output_data= NULL;
	size_t output_data_len = 0;

	// TA_DecryptTest(key_id); 调用测试函数，进行加密解密测试
	res = TEE_OpenPersistentObject(
			TEE_STORAGE_PRIVATE,        // 私有存储
			key_id, strlen(key_id), // 别名作为对象ID
			TEE_DATA_FLAG_ACCESS_READ,
			&key_handle
		);

	// 获取密钥对应的类型，对称密钥 or 非对称密钥
	res = TA_Get_Key(key_id, &key_type, &key_handle, &key_info);
	if(res != TEE_SUCCESS) {
		EMSG("Failed to get key: %s, res=0x%x", (char *)key_id, res);
		goto error;
	}

	if(key_type < 0) {
		EMSG("Invalid key type for alias: %s", (char *)key_id);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto error;
	}else if (key_type == 1) {
		// 非对称密钥处理
		DMSG("Using asymmetric key for alias: %s", (char *)key_id);
		uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
		res = TEE_AllocateOperation(&op, alg, TEE_MODE_DECRYPT,
				    // key_info.objectSize);  //后续根据算法修改alg
					1024);  //后续根据算法修改alg
		if (res) {
			EMSG("TEE_AllocateOperation(TEE_MODE_DECRYPT, %#" PRIx32 "): %#" PRIx32, alg, res);
			return res;
		}

		res = TEE_SetOperationKey(op, key_handle);
		if (res) {
			EMSG("TEE_SetOperationKey: %#" PRIx32, res);
			goto error;
		}

		// 获取获取密文长度，并为密文分配空间
		res = TEE_AsymmetricDecrypt(op, NULL, 0, input_data, input_data_len, NULL,
				    &output_data_len);
		output_data = TEE_Malloc(output_data_len, 0);
		// 接收密文
		res = TEE_AsymmetricDecrypt(op, NULL, 0, input_data, input_data_len, output_data,
				    &output_data_len);
		if (res) {
			EMSG("TEE_AsymmetricEncrypt: %#" PRIx32, res);
			goto error;
		}
		// 赋值给输出参数
		memcpy(params[2].memref.buffer, output_data, output_data_len);
		params[2].memref.size = output_data_len;
		
	} else if (key_type == 0) {
		// 对称密钥处理
		DMSG("Using symmetric key for alias: %s", (char *)key_id);
		// 这里可以添加对称加密的逻辑
	} 

	return TEE_SUCCESS;

	TEE_FreeOperation(op);
	TEE_CloseObject(key_handle);
error:

	// 释放资源
	if(op!=TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	if(key_handle!=TEE_HANDLE_NULL)
		TEE_CloseObject(key_handle);
	
	return res;		
	
}

static TEE_Result TA_Enc_Data(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	int key_type;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo key_info;
	if (param_types != TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,  
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE)) 
		return TEE_ERROR_BAD_PARAMETERS;

	// 获取密钥名称
	size_t key_id_len = params[0].memref.size;
	void *key_id = TEE_Malloc(key_id_len, TEE_MALLOC_FILL_ZERO);
	memcpy(key_id, params[0].memref.buffer, key_id_len);
	// 确保字符串格式的名称以'\0'结尾
	((char *)key_id)[key_id_len] = '\0';

	// 获取明文
	void *input_data= params[1].memref.buffer;
	size_t input_data_len = params[1].memref.size;
	
	//定义密文
	void *output_data= NULL;
	size_t output_data_len = 0;

	// TA_DecryptTest(key_id); //调用测试函数，进行加密解密测试
	res = TEE_OpenPersistentObject(
			TEE_STORAGE_PRIVATE,        // 私有存储
			key_id, strlen(key_id), // 别名作为对象ID
			TEE_DATA_FLAG_ACCESS_READ,
			&key_handle
		);

	// 获取密钥对应的类型，对称密钥 or 非对称密钥
	res = TA_Get_Key(key_id, &key_type, &key_handle, &key_info);
	if(res != TEE_SUCCESS) {
		EMSG("Failed to get key: %s, res=0x%x", (char *)key_id, res);
		goto error;
	}

	if(key_type < 0) {
		EMSG("Invalid key type for alias: %s", (char *)key_id);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto error;
	}else if (key_type == 1) {
		// 非对称密钥处理
		DMSG("Using symmetric key for alias: %s", (char *)key_id);
		uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
		res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT,
				    // key_info.objectSize);  //后续根据算法修改alg
					1024);  //后续根据算法修改alg
		if (res) {
			EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, key_info.objectSize, res);
			return res;
		}

		res = TEE_SetOperationKey(op, key_handle);
		if (res) {
			EMSG("TEE_SetOperationKey: %#" PRIx32, res);
			goto error;
		}

		// 获取获取密文长度，并为密文分配空间
		res = TEE_AsymmetricEncrypt(op, NULL, 0, input_data, input_data_len, NULL,
				    &output_data_len);
		output_data = TEE_Malloc(output_data_len, 0);
						
		// 接收密文
		res = TEE_AsymmetricEncrypt(op, NULL, 0, input_data, input_data_len, output_data,
				    &output_data_len);
		if (res) {
			EMSG("TEE_AsymmetricEncrypt: %#" PRIx32, res);
			goto error;
		}

		// 赋值给输出参数
		//使用memcpy而非直接赋值指针
		memcpy(params[2].memref.buffer, output_data, output_data_len);
		params[2].memref.size = output_data_len;
		DMSG("output_data_len : %zu", output_data_len);
		for (size_t i = 0; i < output_data_len; i++)
		{
			printf("%02x",((uint8_t *)params[2].memref.buffer)[i]);
		}
		printf("\n");
		
	} else if (key_type == 0) {
		// 对称密钥处理
		DMSG("Using asymmetric key for alias: %s", (char *)key_id);
		// 这里可以添加对称加密的逻辑
	} 

	return TEE_SUCCESS;

	TEE_FreeOperation(op);
	TEE_CloseObject(key_handle);
error:

	// 释放资源
	if(op!=TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	if(key_handle!=TEE_HANDLE_NULL)
		TEE_CloseObject(key_handle);
	
	return res;	

}

static TEE_Result TA_List_Keys (uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	// debug_shm_info();
	
	// 检查参数
	if (param_types != TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INOUT,  
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE)) {
			return TEE_ERROR_BAD_PARAMETERS;
	}
	// 检查输出缓冲区大小
	if (params[0].memref.size < sizeof(struct key_db)) {
		return TEE_ERROR_SHORT_BUFFER;
	}

	struct key_db *keydb = (struct key_db *)params[0].memref.buffer;
	if (!keydb) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(keydb, 0, sizeof(struct key_db));
	keydb->key_count = key_datebase->key_count;
	for (size_t i = 0; i < MAX_KEYS; i++)
		keydb->keys[i] = key_datebase->keys[i];
	
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

	// 执行命令前先打开数据库
	TA_Open_Database(session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	DMSG("has been called");
	// TA_Open_Database(session);
	struct acipher *state = session;

	TEE_CloseObject(key_db_obj);
	TEE_Free(state);
}



TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
		case TA_ACIPHER_CMD_GEN_KEY:
			return TA_Gen_Key(param_types, params);
		case TA_ACIPHER_CMD_LIST_KEY:
			return TA_List_Keys(param_types, params);
		case TA_ACIPHER_CMD_ENCRYPT:
			return TA_Enc_Data(param_types, params);
		case TA_ACIPHER_CMD_DECRYPT:
			return TA_Dec_Data(param_types, params);
		default:
			EMSG("Unknown command 0x%" PRIx32, cmd);
			return TEE_ERROR_BAD_PARAMETERS;
	}

}


