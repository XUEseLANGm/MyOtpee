OP-TEE SPMC tests
=================

Build and run
-------------

Please follow the instructions of :ref:`build-spmc-tests`.

Structure
---------

* `xtest`_ is the |NWd| test application which is used to send multiple |FF-A| messages to the SPMC and to the test SPs in
  the |SWd|. It is part of the `optee_test`_ repository.
* The ``arm-ffa-user`` driver provides access to the FF-A layer from the |NWd| user space. ``xtest`` uses it to send |FF-A|
  messages.
* The test SPs implement various testing functions which can be invoked from ``xtest``.

.. uml:: uml/SpmcTestStructure.puml

Implementation
--------------

* |TS|
    * ``components/service/spm_test`` implements the common code of the test SPs.
    * ``deployments/spm-test*`` are the test SP deployments. There are currently four test SPs to cover various test
      scenarios. SPM test SPs use |FF-A| v1.1 except SPM test SP 2 which uses v1.0 to cover the backwards compatibility test
      of the SPMC.
* `optee_test`_
    * `ffa_spmc_1000.c`_ contains the SPMC test cases of ``xtest``.

SPMC test RPC protocol
----------------------

Tests can invoke the functions of the test SPs via an SPMC test specific RPC interface which is built on top of FF-A direct
messages.

.. list-table:: Test RPC protocol
  :header-rows: 1

  * - Message ID
    - Description
    - ``args[0]``
    - ``args[1]``
    - ``args[2]``
    - ``args[3]``
    - ``args[4]``
  * - EP_TEST_SP
    - Run internal SP tests
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - EP_TEST_SP_COMMUNICATION
    - Test FF-A direct message request
    - ``0x00000001``
    - The destination SP's FF-A endpoint ID
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - EP_TEST_SP_INCREASE
    - Increase each ``param`` value by one and return response
    - ``0x00000002``
    - ``param[0]``
    - ``param[1]``
    - ``param[2]``
    - ``param[3]``
  * - EP_TRY_R_ACCESS
    - Test shared buffer read access
    - ``0x00000003``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - EP_TRY_W_ACCESS
    - Test shared buffer write access
    - ``0x00000004``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - EP_RETRIEVE
    - Do FF-A memory retrieve
    - ``0x00000005``
    - Memory handle LSW
    - Memory handle MSW
    - Sender endpoint ID
    - ``0x00000000``
  * - EP_RELINQUISH
    - Do FF-A memory relinquish
    - ``0x00000006``
    - Memory handle LSW
    - Memory handle MSW
    - Flags
    - ``0x00000000``
  * - EP_SP_MEM_SHARING
    - Test FF-A memory sharing
    - ``0x00000007``
    - Target endpoint's FF-A ID
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - EP_SP_MEM_SHARING_MULTI
    - Test FF-A memory sharing with multiple endpoints
    - ``0x00000008``
    - Target endpoint 1 FF-A ID
    - Target endpoint 2 FF-A ID
    - ``0x00000000``
    - ``0x00000000``
  * - EP_SP_MEM_SHARING_EXC
    - Test exclusive FF-A memory sharing
    - ``0x00000009``
    - Target endpoint's FF-A ID
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - EP_SP_MEM_INCORRECT_ACCESS
    - Negative FF-A memory sharing test
    - ``0x0000000a``
    - Target endpoint's FF-A ID
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - EP_SP_NOP
    - No operation
    - ``0x0000000b``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - EP_TEST_SP_COMMUNICATION_RESPONSE
    - Test FF-A direct message response
    - ``0x0000000c``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``
  * - SP_TEST_OK
    - Successful test response
    - ``0x000000aa``
    - Request specific parameter
    - Request specific parameter
    - Request specific parameter
    - Request specific parameter
  * - SP_TEST_ERROR
    - Error test response
    - ``0x000000ff``
    - Error code
    - ``0x00000000``
    - ``0x00000000``
    - ``0x00000000``

Test cases
----------

The following test cases are defined in ``ffa_spmc_1000.c``:

* 1001: Test basic FF-A communication
    * Try to connect to multiple SPs
    * Have different SPs sending messages to each other
    * Test standard SP messages (partition_info_get, get_own_id, ...)
* 1002: Test FF-A memory
    * Test memory sharing between the |NWd| and the |SWd|
* 1003: Test FF-A memory: SP to SP
    * Test memory sharing between to SPs
* 1004: Test FF-A memory: Access and flags
    * Test the different access modifiers and flags when sharing memory
* 1005: Test FF-A memory: multiple receiver
    * Share a memory region with multiple SPs

--------------

.. _`xtest`: https://optee.readthedocs.io/en/latest/building/gits/optee_test.html
.. _`optee_test`: https://github.com/OP-TEE/optee_test
.. _`ffa_spmc_1000.c`: https://github.com/OP-TEE/optee_test/blob/master/host/xtest/ffa_spmc_1000.c


*Copyright (c) 2024, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause