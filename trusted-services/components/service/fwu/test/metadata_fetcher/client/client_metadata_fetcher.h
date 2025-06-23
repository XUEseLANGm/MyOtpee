/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CLIENT_METADATA_FETCHER_H
#define CLIENT_METADATA_FETCHER_H

#include "service/fwu/test/fwu_client/fwu_client.h"
#include "service/fwu/test/metadata_fetcher/metadata_fetcher.h"

/*
 * A metadata_fetcher that fetches fwu metadata using the FWU
 * ABI streaming interface via an fwu_client. This relies on
 * support for streamed reading of metadata via the public
 * service interface. A suitable fwu_client must be constructed
 * with 'new' and exclusive ownership passed to the
 * client_metadata_fetcher via its constructor. The
 * client_metadata_fetcher is responsible for deleting the
 * fwu_client when it no longer needs it.
 */
class client_metadata_fetcher : public metadata_fetcher {
public:
	explicit client_metadata_fetcher(fwu_client *fwu_client);

	~client_metadata_fetcher();

	void open();
	void close(void);
	void fetch(uint8_t *buf, size_t buf_size);

private:
	fwu_client *m_fwu_client;
};

#endif /* CLIENT_METADATA_FETCHER_H */
