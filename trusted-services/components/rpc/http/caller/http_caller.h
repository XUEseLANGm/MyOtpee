/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HTTP_CALLER_H
#define HTTP_CALLER_H

#include <stdbool.h>
#include <stdint.h>

#include "rpc_caller.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HTTP_CALLER_MAX_URL_LEN (2048)

/*
 * An RPC caller that makes call requests via a REST API 'call' endpoint
 * that provides a generic way to call trusted service operations via HTTP.
 * The fw-test-api supports a call endpoint with the path:
 * /services/{servicename}/call/{opcode}. A call request body carries the
 * rpc header defined in protocols/rpc/common/packed-c.header.h, followed by
 * serialized call parameters. A call response body carries the response header
 * defined in the same file, followed by any serialized response parameters.
 */
struct http_caller {
	struct rpc_caller rpc_caller;
	char rpc_call_url[HTTP_CALLER_MAX_URL_LEN];
	size_t req_body_size;
	uint8_t *req_body_buf;
	uint8_t *resp_body_buf;
};

struct rpc_caller *http_caller_init(struct http_caller *s);
void http_caller_deinit(struct http_caller *s);

bool http_caller_probe(const char *url, long *http_code);

int http_caller_open(struct http_caller *s, const char *rpc_call_url);
int http_caller_close(struct http_caller *s);

#ifdef __cplusplus
}
#endif

#endif /* HTTP_CALLER_H */
