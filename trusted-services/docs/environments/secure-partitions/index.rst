Secure Partitions
=================

:term:`Secure Partitions<Secure Partition>` are defined by the :term:`FF-A` standard

Secure partitions are isolated processing environments managed by a Secure Partition Manager (SPM).
An SPM performs the role of hypervisor for the Arm Secure State and is responsible for managing
SP initialization, memory management and messaging. The Arm Firmware Framework for A-Profile (FF-A)
specification (`FF-A Specification`_) defines the set of firmware features that enable the use of
secure partitions for protecting sensitive workloads.

The Armv8.4 architecture introduces the virtualization extension in the Secure state. For silicon
based on Armv8.4 (or above) that implement the Secure-EL2 extension, the `Hafnium Project`_
provides a reference SPMC implementation. For pre-Arm8.4 silicon, the `OP-TEE Project`_ provides
an alternative reference SPMC implementation.

Within the Trusted Services, the environments realized by the two reference SPM implementations
are named as follows:

    * *hfsp* - for service deployment under Hafnium
    * *opteesp* - for service deployment under OP-TEE

.. toctree::
    :maxdepth: 1
    :caption: Contents:

    ff-a/index
    spm/optee/index
    spm/hafnium/index
    libsp

--------------

.. _`FF-A Specification`: https://developer.arm.com/documentation/den0077/latest
.. _`Hafnium Project`: https://www.trustedfirmware.org/projects/hafnium/
.. _`OP-TEE Project`: https://www.trustedfirmware.org/projects/op-tee/

*Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
