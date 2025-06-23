Secure Storage Service
======================
Overview
--------
The Secure Storage service provides a generic persistent object store for valuable
assets such as cryptographic keys.  The confidentiality and integrity of stored data
is typically achieved using keys that are bound to the device.  The backend object
store can be implemented in different ways, depending on available hardware such as:

  * On-SoC secure world peripherals such as NV counters.
  * A hardware unique key stored in OTP.
  * Internal flash (on-die or in package).
  * On-SoC crypto island with persistent storage.
  * RPMB partition in a an external eMMC chip.

The secure storage service provider architecture offers flexibility to use alternative
backend storage implementations to suite available hardware.

Service Access Protocol
-----------------------
A client accesses any instance of the Secure Storage service using a common secure
storage access protocol.  Although multiple secure storage service instances may exist
on a device, they are all accessed using the same access protocol.  By standardizing on
a common protocol, client applications maintain compatibility with any secure storage
provider instance.

The protocol definition lives here::

  protocols/service/secure_storage

PSA Storage Classes
-------------------
Backend storage implementations that rely on external components, such as a flash chip,
will require security measures that are not necessarily needed when on-chip or in-package
storage is used.  The PSA Storage API specification introduces the storage classes
*Protected* and *Internal Trusted* to distinguish between externally and internally provided
storage. These storage class designations are used for naming secure storage service instances.
For example, the secure storage deployment that uses an RPMB backend is referred to as
Protected Storage.  The two storage classes have the following characteristics.  Both
classes of storage are required to support the notion of data ownership and to implement
access control based on policy set by the owner.

Internal Trusted Storage
''''''''''''''''''''''''
Internal trusted storage uses isolated or shielded locations for storage.  Example
storage backends could be on-die or in package flash memory that is inherently secure.
Alternatively, storage may be delegated to an on-die secure enclave that offers equivalent
security properities.  An external storage device may also be used, as long as there is a
cryptographic binding between the owning secure partition and the stored data that prevents
unauthorized access to the storage device.

To provide a persisent store for fundamental objects such as device ID and trust anchor
certificates, access control based on the secure lifecycle state should be possible to
support access policies such as r/w during manufacture but read-only in all other lifecycle
states.

Protected Storage
'''''''''''''''''
Protected storage uses an external memory device for persistent storage.  To meet PSA
security goals, the following protection measures should exist:

  * Privacy and integrity protection to prevent data access and modification by an
    unauthorized agent.
  * Replay protection to prevent the current set of stored data being replaced by an
    old set.

Common implementation options for a protected store are:

  * RPMB partition in an eMMC device.  Access to the device is brokered by a normal-world
    agent such as tee-supplicant.
  * Dedicated serial flash device with secure-world only access.
  * Normal-world filesystem for backend storage.  Data is encrypted and integrity protected
    in the secure-world.

PSA Storage C API
-----------------
For client application developers who wish to use the PSA Storage API to access secure
storage, two storage frontends are available; one that implements the Protected Storage
API and another that implements the Internal Trusted Storage API.

Storage Frontend and Backend Separation
---------------------------------------
For flexibility, secure storage components are separated between frontend and backend.
All storage backends implement a common public interface and may be used with any storage
frontend.  A storage frontend presents an interface that suites a particular type of consumer.
The following class diagram illustrates how a storage frontend is decoupled from any concrete
storage backend through the use of an abstract storage backend interface.

.. uml:: uml/SecureStorageClassDiagram.puml

Some example storage frontends:

  * Secure storage service provider - provides access using the secure storage access protocol.
  * ITS frontend - provides secure storage access via PSA Internal Trusted Storage C API
  * PS frontend - provides secure storage access via PSA Protected Storage C API

Some example storage backends:

  * RPMB storage backend
  * Secure enclave storage backend
  * Normal-world filesystem backend
  * Secure storage service client

Components related to storage frontends and backends live under the following TS project directories::

  components/service/secure_storage/frontend
  components/service/secure_storage/backend

Storage Frontend and Backend Responsibilities
---------------------------------------------
A storage frontend is responsible for presenting an interface that is suitable for a particular
type of consumer.  For example, the Mbed TLS library depends on the PSA Internal Trusted Storage C
API for accessing persistent storage.  The ITS frontend provides an implementation of this API at
its upper edge.  Where appropriate, a storage frontend will be responsible for sanitizing input
parameters.

A storage backend is responsible for:

  * Realizing the common storage backend interface.
  * Implementing per object access control based on the provided client ID.  The client ID associated
    with the creator of an object is treated as the object owner.
  * Providing persistent storage with appropriate security and robustness properties.

Storage Factory
---------------
To decouple generic code from environment and platform specific code, a storage factory
interface is defined that provides a common interface for constructing storage backends.
A concrete storage factory may use environment specific methods and configuration to construct
a suitable storage backend.  Allows new storage backends to be added without impacting service
provider implementations. The factory method uses PSA storage classifications to allow a
service provider to specify the security characteristics of the backend. How those security
characteristics are realized will depend on the secure processing environment and platform.

A concrete storage factory may exploit any of the following to influence how the storage
backend is constructed:

  * Environment and platform specific factory component used in deployment
  * Runtime configuration e.g. from Device Tree
  * The PSA storage classification specified by the SP initialization code.

Concrete storage factory components live under the following TS project directory::

  components/service/secure_storage/factory

Storage Frontend/Backend Combinations
-------------------------------------
The following storage frontend/backend combinations are used in different deployments.

Persistent Key Store for Crypto Service Provider
''''''''''''''''''''''''''''''''''''''''''''''''
The Crypto service provider uses the Mbed Crypto portion of Mbed TLS to implement crypto
operations.  Persistent keys are stored via the PSA Internal Trusted Storage C API.
In the opteesp and sp deployments of the Crypto service provider, a storage client backend is
used that accesses a secure store provided by a separate secure partition.  The following
deployment diagram illustrates the storage frontend/backend combination used:

.. uml:: uml/InternalTrustedDeploymentDiagram.puml

Proxy for OP-TEE Provided Storage
'''''''''''''''''''''''''''''''''
When service providers are deployed in secure partitions running under OP-TEE, access
to OP-TEE provided secure storage is possible via an S-EL1 SP that hosts a secure storage
provider instance.  The following deployment diagram illustrates how secure storage
access is brokered by an S-EL0 proxy:

.. uml:: uml/ProtectedProxyDeploymentDiagram.puml

--------------

*Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
