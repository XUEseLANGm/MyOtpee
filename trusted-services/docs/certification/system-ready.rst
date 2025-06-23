SystemReady
===========
Arm SystemReady is a compliance certification programme that aims to promote a standardized
view of a platform and its firmware (see: `Arm SystemReady`_). SystemReady may be applied across
different classes of device, represented by different SystemReady bands, from resource constrained
IoT devices through to servers. By standardizing the platform and its firmware, generic operating
systems can be expected to 'just work' on any compliant device.

SystemReady leverages existing open standards such as UEFI. The Trusted Services project
includes service level components that enable UEFI SMM services to be realized, backed by PSA
root-of-trust services. As an alternative to EDK2 StMM, the smm-gateway deployment presents
UEFI compliant SMM service endpoints, backed by the generic Secure Storage and Crypto services.
For more information, see:

    * :ref:`Secure Partition Images`
    * :ref:`UEFI SMM Services`

The UEFI features supported by smm-gateway are designed to meet SystemReady requirements for
the IR band (embedded IoT).

--------------

.. _`Arm SystemReady`: https://developer.arm.com/architectures/system-architectures/arm-systemready

*Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
