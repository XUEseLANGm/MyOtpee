Crypto Service
==============
Overview
--------
The Crypto service provides a rich set of cryptographic operations with the backing
of a private key store.  Clients identify keys using opaque key handles, enabling
cryptographic operations to be performed without exposing key values beyond the
boundary of the service's secure processing environment.  This pattern underpins
the security guarantees offered by the Crypto service.

The set of supported operations is aligned to the PSA Crypto API.  C API functions
are invoked by clients using the Crypto service access protocol.  All types and values
defined by the PSA Crypto C API are projected by the Crypto access protocol.  The
one-to-one mapping between the C API and Crypto access protocol allows developers
to use PSA Crypto documentation and examples to understand details of the protocol.

Supported operations fall into the following categories:

  * Key lifetime management
  * Message signing and signature verification
  * Asymmetric encryption/decryption
  * Random number generation

Service Provider Implementation
-------------------------------
The default crypto service provider uses the Mbed Crypto library to implement backend
operations.   The following diagram illustrates the component dependencies in the crypto
service provider implementation (note that there are many more handlers than
illustrated):

.. uml:: uml/CryptoProviderClassDiagram.puml

The packages illustrated reflect the partitioning of the code into separate directories.
Functionality is partitioned as follows:

Crypto Provider
'''''''''''''''
Implements the set of handlers that map incoming RPC call requests to PSA Crypto API
function calls.  A separate handler function exists for each operation supported by the
service.

Crypto Serializer
'''''''''''''''''
Incoming call request parameters are de-serialized and response parameters serialized
by a serializer.  The trusted services framework allows for the use of alternative
serializers to support different parameter encoding schemes.

Mbed Crypto
'''''''''''
All cryptographic operations are handled by an instance of the Mbed Crypto library.
The library is built with a specific configuration that creates dependencies on the
following:

  * PSA ITS API for persistent key storage
  * External entropy source

Secure Storage
''''''''''''''
Persistent storage of keys is handled by an instance of the Secure Storage service.
The service is accessed via a client that presents the PSA ITS API at its upper edge.
This is needed for compatibility with Mbed Crypto.  As long as it meets security
requirements, any Secure Storage service provider may be used.  An RPC session between
the Crypto and Secure Storage service providers is established during initialization
and is maintained for the lifetime of the Crypto service provider.

Entropy Source
''''''''''''''
Certain cryptographic operations, such as key generation, require use of a
cryptographically secure random number generator.  To allow a hardware TRNG to be used,
the Mbed Crypto library is configured to use an externally provided entropy source.
Any deployment of the service provider must include an implementation of the following
function::

  int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)

For production deployments, an implementation of this function should be provided that
obtains the requested bytes of entropy from a suitable source.  To allow the Crypto
service to be used where no hardware backed implementation is available, a software
only implementation is provided.

--------------

*Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
