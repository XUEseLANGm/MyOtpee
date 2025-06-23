Logging Service
===============

The Logging Service manages a log of events, which can be used to monitor and understand the
operation of the system. The service allows other Secure Partitions to efficiently and securely make
log entries, and it has the potential to implement a logging facility fulfilling the requirements of
in filed deployment. The service can implement complex capabilities like protecting the log from
unauthentic access using cryptography or access control. It has the potential to make SWd logs
accessible to NWd clients in a controlled way.

The service helps implementing a flexible logging strategy extending the capabilities introduced by
the FFA_CONSOLE_LOG calls in `FF-A v1.2`_.

The current integration in TS uses FFA_CONSOLE_LOG for critical and boot-time entries, and the
logging service for other purposes. Deploying the logging SP is optional, and clients will fully
revert to using FFA_CONSOLE_LOG if discovering the Logging Service fails during SP initialization.

The current implementation is a simple pipe sending all messages to an UART assigned to the logging
SP.


Supported Logging backends
--------------------------

Backends represent "output pipes" log messages can be sent to. The output of the pipe can be
connected e.g. to a realtime stream (e.g. a serial line) or to a buffer to be polled by an NWd client.


UART backend
''''''''''''

The UART backend outputs messages to an UART device. It relies on an UART platform adapter that
provides a generic interface to interact with an UART device. The exact driver implementation is to
be provided by the platform.

Testing the Logging Service
---------------------------

The service follows the standard TS test strategy:

  - hardware independent parts are covered by unit and component tests
  - hardware dependent parts are covered by environment tests
  - fitness of end-to-end integration is covered by system tests

Currently the testing is partial and only Environment Test is implemented.

Environment Tests
'''''''''''''''''

The logging SP's UART backend relies on the UART peripheral. Test have been added to the
*env_test* SP deployment to check the basic functionality of the UART device, but the
verification of the results is not possible, as the peripheral does not provide a way
(e.g. error bit) to check whether the printing (*putc*) was successful.
Tests included in the *env_test* SP deployment may be invoked from Linux user-space using the
*ts-remote-test/arm-linux* deployment.

--------------

.. _`FF-A v1.2`: https://developer.arm.com/documentation/den0077/g/?lang=en

*Copyright (c) 2023, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
