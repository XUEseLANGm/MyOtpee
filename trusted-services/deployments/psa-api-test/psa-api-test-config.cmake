#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  Common build configuration for all psa-api-test deployments.
#-------------------------------------------------------------------------------

# Prevents symbols in the psa-api-test executable overriding symbols with
# with same name in libts during dyanmic linking performed by the program
# loader.  This avoid psa crypto api symbols provided by the mbedcrypto
# library from being overridden by the same symbols in the psa-api-test
# executable.
set(CMAKE_C_VISIBILITY_PRESET hidden)
