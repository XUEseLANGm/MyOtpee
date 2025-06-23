libsp
=====

libsp is intended to be used from S-EL0 secure partitions. It contains all
the necessary features for communicating with other components using the FF-A
interfaces.

The implementation is split into multiple layers for easy maintainability and
usage. The structure and the short description of the components of the library
is described below.

For detailed information about the FF-A interfaces please check the
`FF-A specification <https://developer.arm.com/documentation/den0077/a/>`_

The API reference documentation is included in the code.

The components of the following diagram are illustrated as classes but as the
library is written in C they are not real classes. Their purpose is to describe
the interfaces and dependencies of the library's components.

.. uml:: /uml/libsp_functions.puml

SP layer
--------

The SP layer provides convenient high level interface for accessing FF-A
features. The layer has multiple components around the groups of the FF-A
interfaces.

SP RXTX
'''''''

The FF-A calls may utilize a pair or buffers called RXTX buffers for passing
data to the SPM that won't fit into registers. These buffers should be set up
during the initialization phase of the SP, then the FF-A calls can use these in
discovery or memory management calls.

The SP RXTX component provides a high level interface for registering these
buffers. It also enables other components of the SP layer to use these buffers
during FF-A calls without the need of manually passing the buffers to the
functions.

SP memory management
''''''''''''''''''''

The FF-A memory management interfaces involve multiple steps for setting up a
memory transaction. This component gives a set of functions to the user for
doing these transactions in a simple way. The supported memory transactions
follows below:

* Donate

* Lend

* Share

* Retrieve

* Relinquish

* Reclaim

FF-A layer
----------

The FF-A layer provides functions and types for accessing FF-A features through
a C API. This low level API gives full control of the FF-A call parameters.

FF-A API
''''''''

The FF-A API provides wrappers for the FF-A interfaces. These interfaces are
fitted into the following groups:

* Setup and discovery interfaces

* CPU cycle management interfaces

* Messaging interfaces

* Memory management interfaces

The functions of this unit give raw control of all the parameters of the FF-A
calls beside providing basic validity checks for the parameters.

Couple FF-A interfaces have the ability to receive a response which indicates
an interrupt that is meant to be handled by the SP. All these functions call a
common interrupt handler function which is defined in the FF-A API component.
This interrupt handler function should be implemented by the upper layers (in
fact it is implemented by the SP layer or libsp).

FF-A memory descriptors
'''''''''''''''''''''''

The FF-A defines memory descriptors to provide information to the SPM about the
referenced memory areas. These are used by memory transactions like sharing,
lending, etc. This information covers various details like instruction and data
access rights, the endpoints of the transaction, address and size of the area,
and so on. Building and parsing memory transaction structures can be quite
complex and this is what this component addresses.

First of all it provides a type for describing buffers where the transaction
descriptors should be built. Using this type provides safety against buffer
overflows during the transaction build and parse processes.

The transaction data consists of three main sections.

1. A transaction descriptor should be added where the memory region attributes
   are described.

2. Multiple memory access descriptors should be added which specify access for
   each receiver of the memory area.

3. Addresses and sizes of the memory regions can be added.

At this point the transaction data should be ready to passed to the SPM by
invoking the suitable FF-A call.


FF-A internal API
-----------------

The lowest layer implemented in libsp is responsible for wrapping FF-A layer
calls into the SVC conduit. Practically this means an escalation of the
exception level and invoking the SVC handler of the SPM with the suitable
parameters passed in registers.

--------------

*Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
