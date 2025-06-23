/*
 * Copyright (c) 2023, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Based on the driver found in trustedfirmware-a written in assembly (pl011_console.S)
 */

#include <stdint.h>

#include "../../../common/mmio.h"
#include "pl011.h"

#define DEFAULT_CLK_IN_HZ 24000000
#define DEFAULT_BAUDRATE  115200

void uflush(uintptr_t addr)
{
	/* Loop until the transmit FIFO is empty */
	while (mmio_read_32(addr + UARTFR) & PL011_UARTFR_BUSY) {
	};
}

void uputc(uint8_t ch, uintptr_t addr)
{
	/* Prepend '\r' to '\n' */
	if (ch == '\n') {
		/* Check if the transmit FIFO is full */
		while (mmio_read_32(addr + UARTFR) & PL011_UARTFR_TXFF) {
		};
		mmio_write_32(addr + UARTDR, '\r');
	}

	/* Print the actual character */
	while (mmio_read_32(addr + UARTFR) & PL011_UARTFR_TXFF) {
	};
	mmio_write_32(addr + UARTDR, ch);
}

void uart_deinit(uintptr_t addr)
{
	/* Disable uart before programming */
	mmio_write_32(addr + UARTCR, 0);

	/* Wait for the end of transmission */
	uflush(addr);

	/* Flush the transmit FIFO by setting the FEN bit to 0 in the Line Control Register */
	mmio_write_32(addr + UARTLCR_H, 0);
}

int uart_init(uintptr_t addr)
{
	if (!addr)
		return -1;

	uart_deinit(addr);

	/* Program the baudrate */
	uint32_t divisor = (DEFAULT_CLK_IN_HZ * 4) / DEFAULT_BAUDRATE;

	mmio_write_32(addr + UARTIBRD, divisor >> 6);
	mmio_write_32(addr + UARTFBRD, divisor & 0x3f);

	/* FIFO Enabled / No Parity / 8 Data bit / One Stop Bit */
	mmio_write_32(addr + UARTLCR_H, PL011_LINE_CONTROL);

	/* Clear any pending errors */
	mmio_write_32(addr + UARTECR, 0);

	/* Enable tx, rx, and uart overall */
	mmio_write_32(addr + UARTCR, PL011_UARTCR_RXE | PL011_UARTCR_TXE | PL011_UARTCR_UARTEN);

	return 0;
}

