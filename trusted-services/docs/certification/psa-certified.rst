PSA Certified
=============
PSA Certified provides a framework for securing connected devices. Certification demonstrates
that security best practices have been implemented, based on an independent security assessment.
For more information, see: `PSA Certified`_.

PSA Certified defines ten security goals that form the foundation for device security. The
certification process involves an assessment that these security goals have been met. The
Trusted Services project includes service provider components and reference integrations
that a system integrator may use as the basis for creating a platform that meets these goals.

PSA Goals
---------
The following table lists the ten security goals and how the Trusted Services
project helps to achieve them:

.. list-table::
  :widths: 1 2
  :header-rows: 1

  * - PSA Certified Goal
    - Trusted Services Contribution
  * - Unique Identification
    - | A unique device identity, assigned during manufacture, may be stored securely
      | using the Secure Storage trusted service with a suitable platform provided backend.
  * - Security Lifecycle
    - | The Attestation trusted service provides an extensible framework for adding claims
      | to a signed attestation report. The security lifecycle state claim is planned to be
      | added in a future release.
  * - Attestation
    - | A remote third-party may obtain a trusted view of the security state of a device by
      | obtaining a signed attestation token from the Attestation service.
  * - Secure Boot
    - | Secure boot relies on a hardware trust anchor such as a public key hash programmed into
      | an OTP eFuse array. For firmware that uses TF-A, all firmware components are verified
      | during the early boot phase.
  * - Secure Update
    - | Involves cooperation of a trusted service with other firmware components such as the
      | boot loader.
  * - Anti-Rollback
    - | The Secure Storage service provider can be used with arbitrary storage backends, allowing
      | platform specific storage to be used. Where the necessary hardware is available, roll-back
      | protected storage can be provided with a suitable backend.
  * - Isolation
    - | The trusted services architectural model assumes that service isolation is implemented using
      | a hardware backed secure processing environment. A secure partition managed by a Secure
      | Partition Manager is one method for realizing isolation.
  * - Interaction
    - | The FF-A specification defines messaging and memory management primitives that enable
      | secure interaction between partitions. Importantly, the secure partition manager provides
      | a trusted view of the identity of a message sender, allowing access to be controlled.
  * - Secure Storage
    - | The Secure Storage service provider uses a pre-configured storage backend to provide
      | an object store with suitable security properties. Two deployments of the secure storage
      | provider (Internal Trusted Storage and Protected Storage) are included with platform
      | specific storage backends.
  * - Cryptographic Service
    - | The Crypto service provider implements a rich set of cryptographic operations using
      | a protected key store. Key usage is controlled based on the least privileges principle
      | where usage flags constrain permitted operations.

Conformance Test Support
------------------------
To support API level conformance testing, the `PSA Arch Test project`_ provides a rich set
of test suites that allow service implementations to be tested. To facilitate running of
PSA functional API tests, the psa-api-test deployment (see: :ref:`Test Executables`) is
supported which integrates test suites with service clients. This can be used to run tests
on a platform and collect tests results to provide visibility to an external assessor.

--------------

.. _`PSA Certified`: https://www.psacertified.org/
.. _`PSA Arch Test project`: https://github.com/ARM-software/psa-arch-tests.git.

*Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
