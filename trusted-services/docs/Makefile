#!/usr/bin/env make
#
# Copyright (c) 2020, Arm Limited and contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

.SUFFIXES:

.PHNOY: all

RM:=cmake -E rm -rf

all:
	sphinx-build -b html . _build

serve:
	sphinx-autobuild . _build

.PHONY:clean
clean:
	${RM} _build
