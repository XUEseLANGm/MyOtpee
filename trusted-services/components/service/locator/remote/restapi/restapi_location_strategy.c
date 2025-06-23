/*
 * Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "restapi_location_strategy.h"

#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "restapi_location.h"
#include "restapi_service_context.h"
#include "rpc/http/caller/http_caller.h"
#include "service/locator/service_name.h"
#include "trace.h"

/* Maximum wait for an unresponsive API server. During testing, this period
 * may need to accommodate the boot time for a device under test.
 */
#ifndef RESTAPI_LOCATOR_MAX_API_WAIT
#define RESTAPI_LOCATOR_MAX_API_WAIT (120)
#endif

static bool probe_api_server(void)
{
	unsigned int seconds_waited = 0;

	do {
		long http_code = 0;

		if (http_caller_probe(RESTAPI_LOCATOR_API_URL, &http_code))
			return true;

		/* Failed to reach API or received an error response */
		if (http_code == 0) {
			/* It's possible that the device hosting the API server is in the
			 * process of booting up so it's worth waiting and trying again.
			 */
			sleep(1);
			++seconds_waited;

		} else {
			/* The server was reached but it returned an error */
			EMSG("API server HTTP error: %ld", http_code);
			return false;
		}

	} while (seconds_waited < RESTAPI_LOCATOR_MAX_API_WAIT);

	IMSG("API server not reachable");

	return false;
}

static void prepare_service_url(const char *sn, char *url_buf, size_t url_buf_size)
{
	strncpy(url_buf, RESTAPI_LOCATOR_API_URL, url_buf_size);

	size_t url_len = strnlen(url_buf, url_buf_size);

	assert(url_len < url_buf_size);

	size_t remaining_space = url_buf_size - url_len;

	url_len += sn_read_service(sn, &url_buf[url_len], remaining_space);

	assert(url_len < url_buf_size - 1);

	url_buf[url_len] = '/';
	url_buf[url_len + 1] = '\0';
}

static struct service_context *query(const char *sn, int *status)
{
	*status = -1;

	if (!probe_api_server())
		return NULL;

	/* API server reachable so check if service endpoint exists */
	char service_url[HTTP_CALLER_MAX_URL_LEN];
	long http_code = 0;

	prepare_service_url(sn, service_url, sizeof(service_url));

	if (!http_caller_probe(service_url, &http_code)) {
		if (http_code != 404)
			EMSG("Unexpected HTTP error: %ld", http_code);

		/* Service endpoint not reachable */
		return NULL;
	}

	return restapi_service_context_create(service_url);
}

const struct service_location_strategy *restapi_location_strategy(void)
{
	static const struct service_location_strategy strategy = { query };

	return &strategy;
}
