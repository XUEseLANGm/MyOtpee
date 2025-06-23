// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 */

#include <service/test_runner/client/cpp/test_runner_client.h>
#include <app/remote-test-runner/remote_test_runner.h>
#include <protocols/rpc/common/packed-c/encoding.h>
#include <service_locator.h>
#include <rpc_caller.h>
#include <cstdio>

int main(int argc, char *argv[]) {
	(void) argc;
	(void) argv;

	int status = -1;
	struct service_context *test_runner_service_context = NULL;

	service_locator_init();

	test_runner_service_context = service_locator_query("sn:trustedfirmware.org:test-runner:0");

	if (test_runner_service_context) {

		struct rpc_caller_session *session = NULL;

		session = service_context_open(test_runner_service_context);

		if (session) {

			test_runner_client test_runner_client(session);
			remote_test_runner commandline_runner(&test_runner_client);

			status = commandline_runner.execute(argc, argv);

			if (status != 0) {
				printf("Command failed with test status: %d rpc status: %d\n", status, test_runner_client.err_rpc_status());
			}

			service_context_close(test_runner_service_context, session);
		}
		else {
			printf("Failed to open rpc session\n");
		}

		service_context_relinquish(test_runner_service_context);
	}
	else {
		printf("Failed to discover test_runner service\n");
	}

	return status;
}
