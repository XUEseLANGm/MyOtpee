/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PROXY_FWU_DUT_H
#define PROXY_FWU_DUT_H

#include "service/fwu/test/fwu_dut/fwu_dut.h"

/*
 * A proxy_fwu_dut is an fwu_dut that acts as a proxy for a full fwu_dut
 * with access to updatable firmware. The proxy_fwu_dut is used in test
 * integrations where the fwu service is being accessed via RPC e.g. from
 * Nwd.
 */
class proxy_fwu_dut : public fwu_dut {
public:
	/**
	 * \brief proxy_fwu_dut constructor
	 *
	 * \param[in]  num_locations  The number of updatable fw locations
	 * \param[in]  metadata_version  FWU metadata version supported by bootloader
	 * \param[in]  remote_dut  The associated remote fwu dut
	 */
	proxy_fwu_dut(unsigned int num_locations, unsigned int metadata_version,
		      fwu_dut *remote_dut);

	~proxy_fwu_dut();

	void boot(bool from_active_bank);
	void shutdown(void);

	struct boot_info get_boot_info(void) const;

	metadata_checker *create_metadata_checker(bool is_primary) const;
	fwu_client *create_fwu_client(void);

private:
	unsigned int m_num_locations;
	fwu_dut *m_remote_dut;
};

#endif /* PROXY_FWU_DUT_H */
