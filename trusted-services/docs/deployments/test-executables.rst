Test Executables
================
The Trusted Services project maintains a number of deployments concerned with
test. Although there may be some coverage overlap between different deployments,
in general, the built test executables corresponding to different deployments
serve different purposes. Most test executables may be run either on target
hardware or a development PC as a native application. For more information, see:
:ref:`Running Tests`.

The following test deployments are currently supported:

component-test
--------------
The component-test deployment combines a large set of tests and components into
a monolithic image that may be run as a userspace application. The CppUtest test
framework is used for running tests and capturing results. The component-test
executable may be built and run very quickly to obtain a first pass check for
build failures or regressions.

.. list-table::
  :widths: 1 2
  :header-rows: 0

  * - Supported Environments
    - * | *linux-pc*
      * | *arm-linux*
  * - Used for
    - * | Build testing
      * | Development support and debug
      * | Regression testing

ts-service-test
---------------
The ts-service-test deployment combines test suites that exercise service providers
via their standard service interfaces where test cases perform the role of service client.
Service discovery and RPC messaging is handled by the *libts* shared library. On real targets,
the *libts* library uses a dynamic discovery mechanism to locate and communicate with real
service deployments. For native PC builds, service providers are embedded into the *libts*
library itself, allowing service level testing within a native PC environment.

.. list-table::
  :widths: 1 2
  :header-rows: 0

  * - Supported Environments
    - * | *linux-pc* - tests against service providers integrated into *libts*
      * | *arm-linux* - tests against real service deployments
  * - Used for
    - * | End-to-end service testing
      * | Security testing
      * | Development support and debug
      * | Regression testing

uefi-test
---------
The uefi-test deployment includes service level tests for UEFI SMM services.

.. list-table::
  :widths: 1 2
  :header-rows: 0

  * - Supported Environments
    - * | *linux-pc* - tests against service providers integrated into *libts*
      * | *arm-linux* - tests against real service deployments using MM_COMMUNICATE
  * - Used for
    - * | UEFI service level testing
      * | Regression testing

psa-api-test
------------
Used for PSA API conformance testing using test suites from: `PSA Arch Test project`_.
Tests are integrated with service clients to enable end-to-end testing against deployed
service providers. Separate executables are built for each API under test. As with
ts-service-test and uefi-test, service discovery and messaging is handled by *libts*,
allowing API tests to be run on real targets or within a native PC environment.

.. list-table::
  :widths: 1 2
  :header-rows: 0

  * - Supported Environments
    - * | *linux-pc* - tests against service providers integrated into *libts*
      * | *arm-linux* - tests against real service deployments
  * - Used for
    - * | PSA API conformance testing
      * | Regression testing

ts-remote-test
--------------
The ts-remote-test deployment builds a userspace application that allows a remote
test runner to be discovered and controlled. It implements a subset of the the
CppUtest command line interface but instead of running tests directly, it
communicates with the remote test runner to run tests and collect results. Can
be used, for example, to control the running of tests included in the env-test
deployment.

.. list-table::
  :widths: 1 2
  :header-rows: 0

  * - Supported Environments
    - * | *linux-pc* - tests against test runner service provider integrated into *libts*
      * | *arm-linux* - tests against real test runner deployment e.g. env-test
  * - Used for
    - * | Running environment tests

--------------

.. _`PSA Arch Test project`: https://github.com/ARM-software/psa-arch-tests.git

*Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
