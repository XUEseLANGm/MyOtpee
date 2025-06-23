/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __STORAGE_BACKEND_H__
#define __STORAGE_BACKEND_H__

#include <stdint.h>
#include <stddef.h>
#include <psa/storage_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Common storage backend interface
 *
 * A concrete storage backend provides an implementation of this
 * interface.
 */
struct storage_backend_interface
{
    /**
     * \brief Create a new, or modify an existing, uid/value pair
     *
     * Stores data in the storage backend.
     *
     * \param[in] context       The concrete backend context
     * \param[in] client_id     Identifier of the asset's owner (client)
     * \param[in] uid           The identifier for the data
     * \param[in] data_length   The size in bytes of the data in `p_data`
     * \param[in] create_flags  The flags that the data will be stored with
     *
     * \return A status indicating the success/failure of the operation
     *
     * \retval PSA_SUCCESS                     The operation completed successfully
     * \retval PSA_ERROR_NOT_PERMITTED         The operation failed because the
     *                                         provided `uid` value was already
     *                                         created with
     *                                         PSA_STORAGE_FLAG_WRITE_ONCE
     * \retval PSA_ERROR_NOT_SUPPORTED         The operation failed because one or
     *                                         more of the flags provided in
     *                                         `create_flags` is not supported or is
     *                                         not valid
     * \retval PSA_ERROR_INSUFFICIENT_STORAGE  The operation failed because there
     *                                         was insufficient space on the
     *                                         storage medium
     * \retval PSA_ERROR_STORAGE_FAILURE       The operation failed because the
     *                                         physical storage has failed (Fatal
     *                                         error)
     * \retval PSA_ERROR_INVALID_ARGUMENT      The operation failed because one
     *                                         of the provided pointers (`p_data`)
     *                                         is invalid, for example is `NULL` or
     *                                         references memory the caller cannot
     *                                         access
     */
    psa_status_t (*set)(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_length,
                            const void *p_data,
                            uint32_t create_flags);

    /**
     * \brief Retrieve data associated with a provided UID
     *
     * Retrieves up to `data_size` bytes of the data associated with `uid`, starting
     * at `data_offset` bytes from the beginning of the data. Upon successful
     * completion, the data will be placed in the `p_data` buffer, which must be at
     * least `data_size` bytes in size. The length of the data returned will be in
     * `p_data_length`. If `data_size` is 0, the contents of `p_data_length` will
     * be set to zero.
     *
     * \param[in]  context        The concrete backend context
     * \param[in]  client_id      Identifier of the asset's owner (client)
     * \param[in]  uid            The uid value
     * \param[in]  data_offset    The starting offset of the data requested
     * \param[in]  data_size      The amount of data requested
     * \param[out] p_data_length  On success, this will contain size of the data
     *                            placed in `p_data`.
     *
     * \return A status indicating the success/failure of the operation
     *
     * \retval PSA_SUCCESS                 The operation completed successfully
     * \retval PSA_ERROR_DOES_NOT_EXIST    The operation failed because the
     *                                     provided `uid` value was not found in
     *                                     the storage
     * \retval PSA_ERROR_STORAGE_FAILURE   The operation failed because the
     *                                     physical storage has failed (Fatal
     *                                     error)
     * \retval PSA_ERROR_INVALID_ARGUMENT  The operation failed because one of the
     *                                     provided arguments (`p_data`,
     *                                     `p_data_length`) is invalid, for example
     *                                     is `NULL` or references memory the
     *                                     caller cannot access. In addition, this
     *                                     can also happen if `data_offset` is
     *                                     larger than the size of the data
     *                                     associated with `uid`.
     */
    psa_status_t (*get)(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_offset,
                            size_t data_size,
                            void *p_data,
                            size_t *p_data_length);

    /**
     * \brief Retrieve the metadata about the provided uid
     *
     * Retrieves the metadata stored for a given `uid` as a `secure_storage_response_get_info`
     * structure.
     *
     * \param[in]  context    The concrete backend context
     * \param[in]  client_id  Identifier of the asset's owner (client)
     * \param[in]  uid        The `uid` value
     * \param[out] p_info     A pointer to the `psa_storage_info_t` struct that will
     *                        be populated with the metadata
     *
     * \return A status indicating the success/failure of the operation
     *
     * \retval PSA_SUCCESS                 The operation completed successfully
     * \retval PSA_ERROR_DOES_NOT_EXIST    The operation failed because the provided
     *                                     uid value was not found in the storage
     * \retval PSA_ERROR_STORAGE_FAILURE   The operation failed because the physical
     *                                     storage has failed (Fatal error)
     * \retval PSA_ERROR_INVALID_ARGUMENT  The operation failed because one of the
     *                                     provided pointers(`p_info`)
     *                                     is invalid, for example is `NULL` or
     *                                     references memory the caller cannot
     *                                     access
     */
    psa_status_t (*get_info)(void *context,
                                uint32_t client_id,
                                uint64_t uid,
                                struct psa_storage_info_t *p_info);

    /**
     * \brief Remove the specified asset from the storage
     *
     * Deletes the data from storage backend.
     *
     * \param[in] context    The concrete backend context
     * \param[in] client_id  Identifier of the asset's owner (client)
     * \param[in] uid        The `uid` value
     *
     * \return A status indicating the success/failure of the operation
     *
     * \retval PSA_SUCCESS                 The operation completed successfully
     * \retval PSA_ERROR_INVALID_ARGUMENT  The operation failed because one or more
     *                                     of the given arguments were invalid (null
     *                                     pointer, wrong flags and so on)
     * \retval PSA_ERROR_DOES_NOT_EXIST    The operation failed because the provided
     *                                     uid value was not found in the storage
     * \retval PSA_ERROR_NOT_PERMITTED     The operation failed because the provided
     *                                     uid value was created with
     *                                     PSA_STORAGE_FLAG_WRITE_ONCE
     * \retval PSA_ERROR_STORAGE_FAILURE   The operation failed because the physical
     *                                     storage has failed (Fatal error)
     */
    psa_status_t (*remove)(void *context,
                                uint32_t client_id,
                                uint64_t uid);

    /**
     * \brief Reserves storage for a new asset
     *
     * Creates a new asset of length zero but with the specified space reserved.
     *
     * \param[in] context       The concrete backend context
     * \param[in] client_id     Identifier of the asset's owner (client)
     * \param[in] uid           The identifier for the data
     * \param[in] capacity      The space to reserve
     * \param[in] create_flags  The flags that the data will be stored with
     *
     * \return A status indicating the success/failure of the operation
     *
     * \retval PSA_SUCCESS                     The operation completed successfully
     * \retval PSA_ERROR_NOT_SUPPORTED         The operation failed because one or
     *                                         more of the flags provided in
     *                                         `create_flags` is not supported or is
     *                                         not valid
     * \retval PSA_ERROR_INSUFFICIENT_STORAGE  The operation failed because there
     *                                         was insufficient space on the
     *                                         storage medium
     * \retval PSA_ERROR_STORAGE_FAILURE       The operation failed because the
     *                                         physical storage has failed (Fatal
     *                                         error)
     * \retval PSA_ERROR_INVALID_ARGUMENT      The operation failed because one
     *                                         of the provided pointers (`p_data`)
     *                                         is invalid, for example is `NULL` or
     *                                         references memory the caller cannot
     *                                         access
     * \retval PSA_ERROR_ALREADY_EXISTS        The specified uuid already exists
     */
    psa_status_t (*create)(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t capacity,
                            uint32_t create_flags);

    /**
     * \brief Set partial data for an existing asset
     *
     * \param[in] context       The concrete backend context
     * \param[in] client_id     Identifier of the asset's owner (client)
     * \param[in] uid           The identifier for the data
     * \param[in] data_offset   Offset into asset for start of write
     * \param[in] data_length   The size in bytes of the data in `p_data`
     *
     * \return A status indicating the success/failure of the operation
     *
     * \retval PSA_SUCCESS                     The operation completed successfully
     *
     * \retval PSA_ERROR_NOT_PERMITTED         The operation failed because the
     *                                         provided `uid` value was already
     *                                         created with
     *                                         PSA_STORAGE_FLAG_WRITE_ONCE
     * \retval PSA_ERROR_NOT_SUPPORTED         The operation failed because one or
     *                                         more of the flags provided in
     *                                         `create_flags` is not supported or is
     *                                         not valid
     * \retval PSA_ERROR_STORAGE_FAILURE       The operation failed because the
     *                                         physical storage has failed (Fatal
     *                                         error)
     * \retval PSA_ERROR_INVALID_ARGUMENT      The operation failed because one
     *                                         of the provided pointers (`p_data`)
     *                                         is invalid, for example is `NULL` or
     *                                         references memory the caller cannot
     *                                         access
     * \retval PSA_ERROR_DOES_NOT_EXIST        The specified uuid was not found
     * \retval PSA_ERROR_DOES_DATA_CORRUPT     Existing data is corrupted
     * \retval PSA_ERROR_INVALID_SIGNATURE     MAC check failed on existing data
     */
    psa_status_t (*set_extended)(void *context,
                            uint32_t client_id,
                            uint64_t uid,
                            size_t data_offset,
                            size_t data_length,
                            const void *p_data);

    /**
     * \brief Get supported features
     *
     * Returns a bit map of optional features supported by the backend
     *
     * \param[in] context       The concrete backend context
     * \param[in] client_id     Identifier of the asset's owner (client)
     *
     * \return Bit map of supported features (defined in psa/storage_common.h)
     */
    uint32_t (*get_support)(void *context,
                            uint32_t client_id);
};

/**
 * \brief Common storage backend instance
 *
 * Used by a storage frontend to make an association with a backend.
 */
struct storage_backend
{
    /**
     * \brief The backend context
     *
     * Points to bandend specific instance data.
     */
    void *context;

    /**
     * \brief The backend interface
     *
     * A concrete backend provides an implementation of this interface.
     */
    const struct storage_backend_interface *interface;
};

#ifdef __cplusplus
}
#endif

#endif /* __STORAGE_BACKEND_H__ */
