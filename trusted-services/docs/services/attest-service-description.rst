Attestation Service
===================
Overview
--------
The Attestation service is responsible for reporting on the security state of a device.
Because information is signed, a remote party may verify that the information is intact
and authentic.  The Attestation service can be used as part of an infrastructure for
remote security monitoring.  The Attestation service provider performs the following
functions:

  1. Collates information about device hardware and firmware.  This information must be obtained in a secure way to provide a suitably trustworthy snapshot of a device's security state.
  2. Prepares and signs a report that includes the information as a set of claims about the device.

Like other trusted services, the Attestation service provider runs within a secure
processing environment such as a secure partition or secondary MCU.  Service operations
are invoked by clients using a service access protocol that defines the serialization of
requests and responses carried by the underlying RPC layer.  Client-side adapters are
available that support service access using the following C APIs:

  - **PSA Initial Attestation API** - used during normal device operation to obtain a fresh attestation token.
  - **Attestation Provisioning API** - used during manufacture for key provisioning operations.

Project Directories
-------------------
Components within the Trusted Services project related to the Attestation service are
located under the following directories:

.. list-table::
  :header-rows: 1

  * - Directory
    - Contains
  * - components/service/attestation
    - Service specific code and API header files.
  * - protocols/service/attestation
    - Service access protocol definitions.
  * - deployments/attestation
    - Build files and deployment specific code for building the attestation service provider to run in different environments.
  * - deployments/platform-inspect
    - A user-space application that retrieves information about platform firmware and hardware and produces a pretty printed output.

Attestation report
------------------
A fresh attestation report may be requested at any time to obtain the current view
of a device's security state.  The report is encoded as a CBOR token, signed using
the CBOR Object Signing and Encryption protocol (COSE).  For more information about
the report contents and encoding, see:
https://www.psacertified.org/blog/what-is-an-entity-attestation-token/.  The following
text shows the typical content of an attestation report.  This report was retrieved
and decoded using the *platform-inspect* command line application::

  attestation_report:
    challenge:  32 2d 69 64 ba df b2 f3 28 e8 27 88 50 68 c2 94 7c 4d a9 71 ce 14 e9 f4 88 26 45 9d 2c f5 3c 1b
    client_id:  0
    boot_seed:  6c eb 03 90 46 e2 09 27 f2 1c 7c a2 2c 1a a6 a2 bd 41 5e 3c aa be 4a b1 fd 35 52 95 b9 74 32 42
    security_lifecycle: 3000
    instance_id:    01 cb e9 65 fc 88 90 69 36 4b b1 0c ef 04 ae 97 aa d7 7c f9 74 41 4d f5 41 0c d3 9d e3 df 97 de c5
    sw_components:
      type:   BL_2
      digest: a8 4f b4 7b 54 d9 4b ab 49 73 63 f7 9b fc 66 cb 85 12 ab 18 6f 24 74 01 5d cf 33 f3 80 9e 9b 20

      type:   BL_31
      digest: 2f d3 43 6c 6f ef 9b 11 c2 16 dd 1f 8b df 9b a5 24 14 a5 c1 97 0c 3a 6c 78 bf ef 64 0f c1 23 e1

      type:   HW_CONFIG
      digest: f3 de 4e 17 a1 a5 a7 fe d9 d9 f4 16 3c 49 36 7e ae f7 2f 2a a8 87 e6 b6 22 89 cd 27 dc 1c 80 25

      type:   SOC_FW_CONFIG
      digest: 4e e4 8e 5a e6 50 ed e0 b5 a3 54 8a 1f d6 0e 8a ea 0e 71 75 0e a4 3f 82 76 ce af cd 7c b0 91 e0

      type:   BL_32
      digest: 62 22 4f 0f b0 5d b4 77 1b 3f a5 2e ab 76 1e 61 17 b8 c6 6e ac 8c c8 4d 2e b0 7d 70 08 60 4b 41

      type:   BL32_EXTRA1_IMAGE
      digest: 39 d2 b8 5d 93 5d f6 d8 f8 ed 0c 1a 3a e3 c8 90 72 19 f4 88 5c 79 15 05 7b f0 76 db c1 4c 5d 77

      type:   BL_33
      digest: b5 d6 08 61 dd fa 6d da a3 f7 a5 de d6 8f 6f 39 25 b1 57 fa 3e db 46 42 58 24 8e 81 1c 45 5d 38

      type:   NT_FW_CONFIG
      digest: 25 10 60 5d d4 bc 9d 82 7a 16 9f 8a cc 47 95 a6 fd ca a0 c1 2b c9 99 8f 51 20 ff c6 ed 74 68 5a

Design Description
------------------
Components related to the Attestation service are partitioned as follows:

.. uml:: uml/AttestPartitioning.puml

The partitioning into components reflects the following problem areas:

.. list-table::
  :header-rows: 1

  * - Component
    - Problem Area
  * - claims
    - Collecting diverse information about a device and presenting it in a uniform way.  Provides an extensible framework that allows new sources of information to be added while avoiding coupling to other components.
  * - client
    - Client side adapters for calling service operations.
  * - key_mngr
    - Manages provisioning related operations and access to the key (IAK) used for report signing.
  * - reporter
    - Combines the set of claims that forms the content of an attestation report, encoding it and signing using the IAK.
  * - provider
    - The service provider that handles incoming requests.
  * - protocol
    - The service access protocol definition that describes supported operations and the serialization of input and output parameters.

Claims Model
''''''''''''
The set of available claims about a device and the method for obtaining them is likely to
vary between different platforms.  The following are examples of likely variations:

  - The method for collecting boot measurements will depend on the boot loader and on SoC architecture.  Some likely variations are:

    - Passed forward using a TPM event log or via a proprietary format.
    - Boot measurements are stored in TPM PCR type registers that need to be read to obtain claims about loaded components.
  - The set of information passed forward by the boot loader may vary between platforms.  Information such as the boot seed or device lifecycle state may be owned by the boot loader on some platforms but not on others.
  - Platform vendors may wish to include custom claims within the attestation report that reflect vendor specific views of security state.

To accommodate these variations, a flexible claims model is implemented with the following
characteristics:

  - Any claim is represented by a common structure with members to identify:

    - The category of claim - e.g. this is a claim about device hardware, firmware, the verification service.
    - The subject of the claim - a claim specific identifier
    - A variant id to identify the data type for a claim - e.g. integer, byte string, text string or a collection.
  - Arbitrarily complex claim structures may be presented in a normalized way using combinations of claim variants.
  - Claims are collected by a set of 'claim sources'.  Each concrete claim source implements the platform specific method for collecting information and representing it in standard way.  The set of claim sources used may vary for different deployments.
  - Claim sources are registered with the claims_register.  This is a singleton that provides methods for querying for different sets of claims e.g. all device claims or all firmware measurements.  By collating claims by category, tight coupling between the reporter and the set of available claims is avoided.

The following class diagram illustrates the implemented claims model:

.. uml:: uml/AttestClaimsModel.puml

Claim Sources
"""""""""""""
It is envisaged that the number of concrete claim sources will grow to cope with differences
between platforms and the need to include custom claims in attestation reports.  The following
table lists some existing claim sources:

.. list-table::
  :header-rows: 1

  * - Claim Source
    - Description
  * - event_log
    - A claim source that sources a claim_collection variant.  An iterator may be created that allows claims within a TCG event log to be iterated over and accessed.
  * - boot_seed_generator
    - Where a boot seed is not available from another source, a boot_seed_generator may be used in a deployment.  On the first call to get_claim(), a random boot seed is generated and returned as a byte_string claim variant.  On subsequent calls, the same boot seed value is return.
  * - instance_id
    - A claim source that returns a device instance ID, derived from the IAK public key.
  * - null_lifecycle
    - Used when there is no hardware backed support for the device lifecycle state variable.  This claim source just returns a lifecycle state of 'unknown'.

Reporter
""""""""
The contents of the attestation report created by the reporter is determined by the set of
claim sources registered with the claims_register.  To generate a PSA compliant attestation
report, the reporter queries for the following categories of claim:

  - Device
  - Verification service
  - Boot measurements

Having collated all claims, the report is serialized as a CBOR object using the qcbor
open source library.  The CBOR object is then signed using the *t_cose* library to produce
the final attestation token.

Provisioning Flows
------------------
The Attestation service uses the IAK (an ECDSA key pair) for signing attestation reports.
An external verification service needs a way of establishing trust in the IAK used by a
device to sign a report.  This trust relationship is formed when a device is provisioned
during manufacture.  During provisioning, the following steps must be performed in a
secure manufacturing environment:

  1.  A unique IAK is generated and stored as a persistent key in the device's secure key store.
  2.  The IAK public key is obtained and stored in a central database of trusted devices.  The hash of the IAK public key (the device's instance ID) is used as the database key for accessing the stored key.

To verify the authenticity of an attestation report, an external verifier must query
the database using the instance ID claim contained within the report.  The signature on
the report is viewed as authentic if the following are true:

  - A key record exists for the given instance ID within the database.
  - The signature is verified successfully using the corresponding public key.

The attestation access protocol supports operations to support provisioning.  These
operations may be invoked using simple client C API (see *attest_provision.h*) or by
using the access protocol directly for non-C clients.  The following two alternative
provisioning flows are supported:

Self-generated IAK
''''''''''''''''''
When a device powers up before provisioning has been performed, no IAK will exist in
the device's key store.  As long as no attestation related service operations are
performed, the device will remain in this state.  To trigger the self generation of
an IAK, factory provisioning software should call the *export_iak_public_key* operation.
If no IAK exists, one will be generated using the device's TRNG.  A benefit of this
flow is that the IAK private key value is never externally exposed.  To support test
deployments where no persistent storage is used, the self-generated IAK flow may
optionally generate a volatile key instead of persistent key.:

.. uml:: uml/AttestSelfGeneratedIAKflow.puml

Imported IAK
''''''''''''
To support external generation of the IAK, a one-time key import operation is also
supported.  When a device is in the pre-provisioned state where no IAK exists, the
import_iak may be called by factory provisioning software.  Importantly, *import_iak*
may only be called once.  An attempt to call it again will be rejected.:

.. uml:: uml/AttestImportedIAKflow.puml

Testing the Attestation Service
-------------------------------
The following CppUtest based test suites are available for attestation service testing.
All component and service level tests may be run on a real target device and as part
of a native PC built binary.

Component-Level Test Suites
'''''''''''''''''''''''''''
Test suites included in deployments of *component-test*:

.. list-table::
  :header-rows: 1

  * - Test Suite
    - Coverage
    - File Location
  * - TcgEventLogTests
    - Tests decoding and iterator access to a TCG event log.
    - service/attestation/claims/sources/event_log/test
  * - AttestationReporterTests
    - Checks the contents and signing of a generated attestation report.
    - service/attestation/test/component

Service-Level Test Suites
'''''''''''''''''''''''''
Test suites included in deployments of *ts-service-test*.  Test cases act as conventional
service clients:

.. list-table::
  :header-rows: 1

  * - Test Suite
    - Coverage
    - File Location
  * - AttestationServiceTests
    - Different attestation token request scenarios
    - service/attestation/test/service
  * - AttestationProvisioningTests
    - Tests provisioning flows and checks defence against misuse of provisioning operations.
    - service/attestation/test/service

Environment Tests
'''''''''''''''''
When deployed within a secure partition, the attestation SP relies on access to externally
provided information such as the TPM event log.  Test have been added to the *env_test* SP
deployment to check that features that the attestation SP relies on are working as expected.
Tests included in the *env_test* SP deployment may be invoked from Linux user-space using the
*ts-remote-test/arm-linux* deployment.

--------------

*Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
