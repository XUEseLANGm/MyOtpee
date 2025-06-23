/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <cstdio>
#include <CppUTest/CommandLineTestRunner.h>

/* These tests are intended to be compiled natively and run on a PC */
int main(int argc, char *argv[]) {

	return CommandLineTestRunner::RunAllTests(argc, argv);
}