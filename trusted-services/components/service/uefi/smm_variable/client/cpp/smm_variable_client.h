/*
 * Copyright (c) 2021-2023, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SMM_VARIABLE_CLIENT_H
#define SMM_VARIABLE_CLIENT_H

#include <cstdint>
#include <protocols/common/efi/efi_status.h>
#include <protocols/service/smm_variable/smm_variable_proto.h>
#include <string>
#include <vector>
#include <uchar.h>

#include "components/rpc/common/caller/rpc_caller_session.h"

/*
 * Provides a C++ client interface for accessing an instance of the smm-variable service.
 * This client is intended for testing the UEFI variable store provided by the smm-variable
 * service.
 */
class smm_variable_client {
public:
	smm_variable_client();
	smm_variable_client(struct rpc_caller_session *session);
	~smm_variable_client();

	void set_caller_session(struct rpc_caller_session *session);
	int err_rpc_status() const;

	/* Set variable with C string name. */
	efi_status_t set_variable(const EFI_GUID &guid, const char16_t *name,
					       const std::string data, uint32_t attributes);

	efi_status_t set_variable(const EFI_GUID &guid, const char16_t *name,
					       const unsigned char* data, size_t data_length,
					       uint32_t attributes);

	/* Set character array variable */
	efi_status_t set_variable(const EFI_GUID &guid, const std::u16string &name,
				  const unsigned char *data, size_t data_length,
				  uint32_t attributes);

	/* Set a string type variable */
	efi_status_t set_variable(const EFI_GUID &guid, const std::u16string &name,
				  const std::string &data, uint32_t attributes);

	efi_status_t set_variable(const EFI_GUID &guid, const std::u16string &name,
				  const std::string &data, uint32_t attributes,
				  size_t override_name_size, size_t override_data_size);

	/* Get a string type variable */
	efi_status_t get_variable(const EFI_GUID &guid, const char16_t *name, std::string &data);
	efi_status_t get_variable(const EFI_GUID &guid, const char16_t *name, std::string &data,
				  size_t override_name_size, size_t max_data_size);

	efi_status_t get_variable(const EFI_GUID &guid, const std::u16string &name,
				  std::string &data);

	efi_status_t get_variable(const EFI_GUID &guid, const std::u16string &name, std::string &data,
				  size_t override_name_size,
				  size_t max_data_size = MAX_VAR_DATA_SIZE);

	/* Remove a variable */
	efi_status_t remove_variable(const EFI_GUID &guid, const char16_t *name);
	efi_status_t remove_variable(const EFI_GUID &guid, const std::u16string &name);

	/* Query variable info */
	efi_status_t query_variable_info(uint32_t attributes, size_t *max_variable_storage_size,
					 size_t *remaining_variable_storage_size,
					 size_t *max_variable_size);

	/* Get the next variable name - for enumerating store contents */
	efi_status_t get_next_variable_name(EFI_GUID &guid, std::u16string &name);

	efi_status_t get_next_variable_name(EFI_GUID &guid, std::u16string &name,
					    size_t override_name_size);

	/* Exit boot service */
	efi_status_t exit_boot_service();

	/* Set variable check properties */
	efi_status_t set_var_check_property(const EFI_GUID &guid, const char16_t *name,
					    const VAR_CHECK_VARIABLE_PROPERTY &check_property);

	efi_status_t set_var_check_property(const EFI_GUID &guid, const char16_t *name,
					    const VAR_CHECK_VARIABLE_PROPERTY &check_property,
					    size_t override_name_size);

	efi_status_t set_var_check_property(const EFI_GUID &guid, const std::u16string &name,
					    const VAR_CHECK_VARIABLE_PROPERTY &check_property);

	efi_status_t set_var_check_property(const EFI_GUID &guid, const std::u16string &name,
					    const VAR_CHECK_VARIABLE_PROPERTY &check_property,
					    size_t override_name_size);

	/* Get variable check properties */
	efi_status_t get_var_check_property(const EFI_GUID &guid, const char16_t *name,
					    VAR_CHECK_VARIABLE_PROPERTY &check_property);

	efi_status_t get_var_check_property(const EFI_GUID &guid, const char16_t *name,
					    VAR_CHECK_VARIABLE_PROPERTY &check_property,
					    size_t override_name_size);

	efi_status_t get_var_check_property(const EFI_GUID &guid, const std::u16string &name,
					    VAR_CHECK_VARIABLE_PROPERTY &check_property);

	efi_status_t get_var_check_property(const EFI_GUID &guid, const std::u16string &name,
					    VAR_CHECK_VARIABLE_PROPERTY &check_property,
					    size_t override_name_size);

	/* Get maximum variable payload size */
	efi_status_t get_payload_size(size_t &payload_size);

private:
	/* Datasize limit set by UEFI specification */
	static const size_t MAX_VAR_DATA_SIZE = 65536;

	efi_status_t rpc_to_efi_status() const;

	std::u16string to_variable_name(const char16_t *name) const;
	void from_variable_name(const int16_t *name, size_t name_size, std::u16string &result);

	struct rpc_caller_session *session;
	int m_err_rpc_status;
};

#endif /* SMM_VARIABLE_CLIENT_H */
