/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "metadata_checker.h"

#include <CppUTest/TestHarness.h>

metadata_checker::metadata_checker(size_t max_metadata_size, metadata_fetcher *metadata_fetcher)
	: m_metadata_fetcher(metadata_fetcher)
	, m_meta_buf(NULL)
	, m_meta_buf_size(max_metadata_size)
{
	m_metadata_fetcher->open();

	m_meta_buf = new uint8_t[m_meta_buf_size];
	CHECK_TRUE(m_meta_buf);
}

metadata_checker::~metadata_checker()
{
	m_metadata_fetcher->close();

	delete[] m_meta_buf;
	m_meta_buf = NULL;

	delete m_metadata_fetcher;
	m_metadata_fetcher = NULL;
}

void metadata_checker::load_metadata(void)
{
	m_metadata_fetcher->fetch(m_meta_buf, m_meta_buf_size);
}