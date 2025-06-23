/*
 * Copyright (c) 2021-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef VARIABLE_CHECKER_H
#define VARIABLE_CHECKER_H

#include <protocols/common/efi/efi_status.h>
#include <protocols/service/smm_variable/smm_variable_proto.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief variable_constraints structure definition
 *
 * Defines constraints used for checking variable set operations
 * based on policy driven constraints, set using:
 * SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_SET.
 */
struct variable_constraints {
	uint16_t revision;
	uint16_t property;
	uint32_t attributes;
	size_t min_size;
	size_t max_size;
};

/**
 * @brief      Set variable check constraints
 *
 * @param[in]  constraints  Variable constraints to set
 * @param[in]  is_update  True if updating previously set constraints
 * @param[in]  check_var_property The incoming check variable properties
 *
 * @return     EFI_SUCCESS if check constraints set successfully
 */
efi_status_t
variable_checker_set_constraints(struct variable_constraints *constraints, bool is_update,
				 const VAR_CHECK_VARIABLE_PROPERTY *check_var_property);

/**
 * @brief      Get variable check constraints
 *
 * @param[in]  constraints  Variable constraints to get
 * @param[out] check_var_property The result
 */
void variable_checker_get_constraints(const struct variable_constraints *constraints,
				      VAR_CHECK_VARIABLE_PROPERTY *check_var_property);

/**
 * @brief      Check if set operations is allowed
 *
 * @param[in]  constraints  Check constraints corresponding to variable
 * @param[in]  attributes  	The attributes to set
 * @param[in]  data_size	The data size
 *
 * @return     EFI_SUCCESS if set is allowed
 */
efi_status_t variable_checker_check_on_set(const struct variable_constraints *constraints,
					   uint32_t attributes, size_t data_size);

#ifdef __cplusplus
}
#endif

#endif /* VARIABLE_CHECKER_H */
