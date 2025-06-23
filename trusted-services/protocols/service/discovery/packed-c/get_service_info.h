/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_DISCOVERY_GET_SERVICE_INFO_H
#define TS_DISCOVERY_GET_SERVICE_INFO_H

#include <stdint.h>

/**
 * Parameter definitions for the GET_SERVICE_INFO operation.
 *
 * Returns information about how to communicate with the service
 * interface.
 */

/* Mandatory fixed sized output parameters */
struct __attribute__ ((__packed__)) ts_discovery_get_service_info_out
{
	/* The RPC interface id that should be used to
	 * communicate with this service provder instance.
	 */
	uint16_t interface_id;

	/* The instance number assigned to this service provider.
	 * Used for identifying a particular instance of a service
	 * provider within a system that may host multiple instances.
	 * This instance may be used as a binding by clients and may be
	 * reflected at the kernel/userspace interface via a device node
	 * with a particular instance e.g. /dev/tpm0.
	 */
	uint16_t instance;

	/* A bitmap of supported access protocol encodings for parameter
	 * serialization.  A service provider may support 1..* encodings.
	 */
	uint32_t supported_encodings;

	/* The maximum supported payloadsize for an RPC call request or
	 * response.  This limit will be imposed by the underlying RPC
	 * layer used by a client to call service operations. If the
	 * maximum payload size is different between call requests and
	 * responses, the smaller value should be used.
	 */
	uint32_t max_payload;
};

/* Variable length output parameter tags */
enum
{
    /* Identifies the service naming authority e.g 'trustedfirmware.org' */
    TS_DISOVERY_GET_SERVICE_INFO_OUT_TAG_NAME_AUTHORITY  = 1,

	/* The service name string assigned by the naming authority e.g. 'crypto' */
	TS_DISOVERY_GET_SERVICE_INFO_OUT_TAG_SERVICE_NAME = 2
};

#endif /* TS_DISCOVERY_GET_SERVICE_INFO_H */
