/*
 * Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TS_PLATFORM_INTERFACE_MHU_H
#define TS_PLATFORM_INTERFACE_MHU_H

/*
 * Interface definition for a platform MHU driver.  A platform provider will
 * provide concrete implementations of this interface for each alternative
 * implementation supported.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Virtual interface for a platform MHU driver.  A platform will provide
 * one or more concrete implementations of this interface.
 */
struct platform_mhu_iface {
    /*
     * \brief Sends data over MHU.
     *
     * \param[in] context         Platform driver context.
     * \param[in] send_buffer     Pointer to buffer containing the data to be
     *                            transmitted.
     * \param[in] size            Size of the data to be transmitted in bytes.
     *
     * \return 0 if successful.
     *
     * \note The send_buffer must be 4-byte aligned and its length must be at least
     *       (4 - (size % 4)) bytes bigger than the data size to prevent buffer
     *       over-reading.
     */
	int (*send)(void *context, unsigned char *send_buffer, size_t size);

    /*
     * \brief Receives data from MHU.
     *
     * \param[in]     context           Platform driver context.
     * \param[out]    receive_buffer    Pointer the buffer where to store the
     *                                  received data.
     * \param[in,out] size              As input the size of the receive_buffer,
     *                                  as output the number of bytes received.
     *                                  As a limitation, the size of the buffer
     *                                  must be a multiple of 4.
     *
     * \return 0 if successful.
     *
     * \note The receive_buffer must be 4-byte aligned and its length must be a
     *       multiple of 4.
     */
	int (*receive)(void *context, unsigned char *receive_buffer, size_t *size);

    /*
     * \brief Wait for data from MHU.
     *
     * \param[in] context           Platform driver context.
     *
     * \return 0 if successful.
     *
     * \note This function must be called before mhu_receive_data() if the MHU
     *       receiver interrupt is not used.
     */
	int (*wait_data)(void *context);

    /*
     * \brief Signals an interrupt over the last available channel and wait for the
     *        values to be cleared by the receiver.
     *
     * \param[in]   context           Platform driver context.
     * \param[in]   value             Value that will be used while signaling.
     *
     * \return 0 if successful.
     */
	int (*signal_and_wait_for_clear)(void *context, uint32_t value);

    /*
     * \brief Wait for signal on the last available channel in a loop and
     *        acknowledge the transfer by clearing the status on that channel.
     *
     * \param[in]     context          Platform driver context.
     * \param[in]     value            Value that will be used while waiting.
     *
     * \return 0 if successful.
     */
	int (*wait_for_signal_and_clear)(void *context, uint32_t value);
};

/*
 * A platform MHU driver instance.
 */
struct platform_mhu_driver {
	void *context; /**< Opaque driver context */
	const struct platform_mhu_iface *iface; /**< Interface methods */
};

/*
 * \brief Factory method to construct a platform specific MHU driver
 *
 * \param[out] driver         Pointer to driver structure to initialize on construction.
 * \param[in]  object_name    Deployment specific name of the instance in the config store.
 * \param[in]  is_receiver    True if the MHU will be used for receiving data, false if sending.
 *
 * \return          0 if successful.
 */
int platform_mhu_create(struct platform_mhu_driver *driver, const char *object_name,
			bool is_receiver);

/*
 * \brief Destroy a driver constructed using the factory method
 *
 * \param[in] driver    Pointer to driver structure for constructed driver.
 */
void platform_mhu_destroy(struct platform_mhu_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* TS_PLATFORM_INTERFACE_MHU_H */
