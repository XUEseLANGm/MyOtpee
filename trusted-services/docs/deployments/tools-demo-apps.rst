Tools & Demo Applications
=========================
The following deployments are concerned with building tools and demo applications.

platform-inspect
----------------
The *platform-inspect* tool may be run from a Linux terminal to inspect and
report information about platform firmware. Functionality is currently limited
to retrieving a firmware attestation report and printing its contents.

.. list-table::
  :widths: 1 2
  :header-rows: 0

  * - Supported Environments
    - * | *linux-pc*
      * | *arm-linux*
  * - Used for
    - * | Obtaining information about platform firmware

ts-demo
-------
*ts-demo* is a simple application that uses the Crypto service to perform some
typical sign, verify and encrypt operations. It is intended to be used as an
example of how trusted services can be used by userspace applications.

.. list-table::
  :widths: 1 2
  :header-rows: 0

  * - Supported Environments
    - * | *linux-pc*
      * | *arm-linux*
  * - Used for
    - * | Provides an example for how to use trusted services

--------------

*Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
