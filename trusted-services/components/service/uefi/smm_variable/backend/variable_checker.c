/*
 * Copyright (c) 2021-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "variable_checker.h"

efi_status_t variable_checker_set_constraints(struct variable_constraints *constraints,
					      bool is_update,
					      const VAR_CHECK_VARIABLE_PROPERTY *check_var_property)
{
	/* Sanity check input parameters */
	if (check_var_property->Revision != VAR_CHECK_VARIABLE_PROPERTY_REVISION)
		return EFI_INVALID_PARAMETER;

	if (check_var_property->MinSize > check_var_property->MaxSize)
		return EFI_INVALID_PARAMETER;

	/* New check constraints accepted */
	constraints->revision = check_var_property->Revision;
	constraints->attributes = check_var_property->Attributes;
	constraints->property = check_var_property->Property;
	constraints->min_size = check_var_property->MinSize;
	constraints->max_size = check_var_property->MaxSize;

	return EFI_SUCCESS;
}

void variable_checker_get_constraints(const struct variable_constraints *constraints,
				      VAR_CHECK_VARIABLE_PROPERTY *check_var_property)
{
	check_var_property->Revision = constraints->revision;
	check_var_property->Attributes = constraints->attributes;
	check_var_property->Property = constraints->property;
	check_var_property->MinSize = constraints->min_size;
	check_var_property->MaxSize = constraints->max_size;
}

efi_status_t variable_checker_check_on_set(const struct variable_constraints *constraints,
					   uint32_t attributes, size_t data_size)
{
	(void)attributes;

	if (constraints->property & VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY)
		return EFI_WRITE_PROTECTED;

	if (data_size < constraints->min_size)
		return EFI_INVALID_PARAMETER;

	if (data_size > constraints->max_size)
		return EFI_INVALID_PARAMETER;

	return EFI_SUCCESS;
}
