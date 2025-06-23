Firmware Framework for Armv8-A
==============================
The |FF-A| specification defines a software architecture that isolates Secure world firmware images from each other. The
specification defines interfaces that standardize communication between various images. This includes communication
between images in the Secure world and Normal world.

The Trusted Services project includes service providers that may be deployed within FF-A S-EL0 secure partitions. This
includes service providers that form the security foundations needed for meeting PSA Certified requirements. Other secure
partitions are available such as the SMM Gateway to provide Secure world backing for UEFI services.

The component :ref:`libsp` captures helpful abstractions to allow easy FF-A compliant S-EL0 SP development. S-EL0 SPs
are SPMC agonistic and can be used with an SPMC running in any higher secure exception level (S-EL1 - S-EL3).

--------------

*Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
