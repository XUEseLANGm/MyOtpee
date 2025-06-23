/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
 */

#ifndef MM_COMMUNICATE_CALL_ARGS_H_
#define MM_COMMUNICATE_CALL_ARGS_H_

/**
 * MM communication protocol is adapted to be used above FF-A direct messages
 * by the following FF-A direct message argument indexes.
 */

/* SP message arg indexes */
#define MM_COMMUNICATE_CALL_ARGS_COMM_BUFFER_OFFSET	0

#define MM_COMMUNICATE_CALL_ARGS_RETURN_CODE		0
#define MM_COMMUNICATE_CALL_ARGS_MBZ0			1
#define MM_COMMUNICATE_CALL_ARGS_MBZ1			2
#define MM_COMMUNICATE_CALL_ARGS_MBZ2			3
#define MM_COMMUNICATE_CALL_ARGS_MBZ3			4

#endif /* MM_COMMUNICATE_CALL_ARGS_H_ */
