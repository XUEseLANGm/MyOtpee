Project Structure
=================

This page describes the directory and repository structure for the trusted services project.

Top-Level Project Organization
------------------------------
The project is organized under the following top-level directories::

    project
        |-- docs
        |-- deployments
        |-- environments
        |-- platforms
        |-- components
        |-- external
        |-- protocols
        |-- tools

Top-level directories are used to organize project files as follows:

docs
''''

The home for project documentation source.

deployments
'''''''''''

A deployment represents the build instance of a service (or in fact any unit of functionality) for a particular
environment.  For each deployment, there is a single deployable output, usually a binary executable.  The
deployment is concerned with configuring and building a particular set of components to run in a particular
environment.  For each supported deployment, there is a leaf sub-directory that lives under a parent.  The
parent directory identifies what's being deployed while the leaf sub-directory identifies where it is being
deployed.  The following example illustrates how the 'what' and 'where' are combined to form fully defined
deployments::

    deployment-name = <descriptive-name>/<environment>

    deployments
        |-- protected-storage/opteesp
        |-- crypto/opteesp
        |-- crypto/sp
        |-- ts-demo/arm-linux
        |-- component-test/linux-pc
        |-- libts/linux-pc

The trusted services project uses CMake to configure and generate build files.  A CMakeLists.txt file exists
for each deployment to define the set of components, any deployment specific configuration and anything
environment specific.  Each deployment leaf directory also holds a source file that defines the main entry
point to allow a particular set of components to be initialized before entering the application that implements
the core functionality of software being deployed.

The directory structure for deployments supports inheritance from the deployment parent to promote reuse of
common definitions and initialization code.  For example, deployments of the secure-storage service for
different environments are likely to have similarities in terms of the set of components used and in subsystem
initialization code.  To avoid duplication between deployments, common cmake and source files may be located
under the deployment parent.  This is illustrated in the following::

    deployments
        |-- secure-storage
                |-- common.cmake            <-- Common cmake file
                |-- service_init.c          <-- Common initialization code
                |-- opteesp
                |       |-- CMakeLists.txt      <-- Includes ../common.cmake to inherit common definitions
                |       |-- opteesp_service_init.c
                |-- sp
                        |-- CMakeLists.txt      <-- Includes ../common.cmake to inherit common definitions
                        |-- opteesp_service_init.c

environments
''''''''''''

An environment represents the execution context in which a built image runs.  There are different environments
represented in the project structure, one for each supported isolated execution context.  Files related to a
particular environment live under a sub-directory whose name describes the environment.  For example:

    - *opteesp*         An S-EL0 secure partition hosted by OP-TEE
    - *sp*              SPMC agnostic S-EL0 secure partition
    - *arm-linux*       Linux user-space, cross compiled for Arm.
    - *linux-pc*        Native PC POSIX environment

Files related to an environment will tend to live outside of the project tree and will need to be imported
in some way.  How this is handled will depend on the environment.  An environment will generally provide the
following:

    - Environment specific libraries that have been externally built.
    - Public header files for libraries.
    - An install method that takes a deployment image and installs it in the environment.
    - Compiler configuration

A deployment will include an environment specific build file (see above) that defines the list of environment
specific components used for a deployment into a particular environment.

opteesp
"""""""

The opteesp environment uses a very similar SP format to the OP-TEE Trusted Applications. It is an ELF file with an OP-TEE
specific header structure at its beginning. The SP image is relocatable and it is handled by the ELF loader (ldelf) component
of OP-TEE. Naturally this environment only works with OP-TEE in the role of the SPMC.

sp
""

Deployments that use the sp environment can produce SPMC agnostic SP images. This environment generates SP images as flat
binaries that can be loaded without an ELF loader. The initialization of the stack and the handling of relocation must be done
in the startup code of the SP. Setting the memory access rights of different sections of the SP image can be either done
thought load relative memory regions in the manifest or by using the ``FFA_MEM_PERM_SET`` interface of the FF-A v1.1
specification in the boot phase of the SP.

Trusted Services first builds ELF files for the sp environment deployments and then it generates the memory region nodes of the
manifest based on the sections of the ELF file. The sections of the ELF is then copied into the flat binary image. The
environment provides the startup file so all the necessary initialization steps are done before the ``sp_main`` call.

platforms
'''''''''

For some deployments, an environment may not provide access to all hardware backed services needed by an
application.  Files under the platforms directory are concerned with configuring and building platform specific
code that extends the capabilities of an environment.  Details of how this works are described in the:
:ref:`Service Deployment Model`

components
''''''''''

Source code lives under the components directory, organized as reusable groups of source files.  A component
is the unit of reuse for code that may be combined with other components to realize the functionality needed
for a deployment.  Creating a new deployment should be just a case of selecting the right set of components
to provide the required functionality for the target environment.  Some components may depend on other
components and others may only make sense in a particular environment.

The components sub-tree has an organization that reflects the layered model where service components are
kept separate from RPC components and so on.  There is also a separation between client components and service
provider components.  The following illustrates this::

    components
        |-- service
        |   |-- common
        |   |       |-- test
        |   |-- secure-storage
        |   |       |-- frontend
        |   |       |-- backend
        |   |       |-- factory
        |   |       |-- test
        |   |-- crypto
        |   |       |-- client
        |   |               |- component.cmake
        |   |       |-- provider
        |-- rpc
        |   |-- common
        |   |-- ffarpc
        |   |       |-- caller
        |   |       |-- endpoint

Each leaf directory under the components parent includes a cmake file called component.cmake.  This is used to
define all files that make up the component and any special defines that are needed to build it.  A deployment
CMakeLists.txt just needs to reference the required set of components.  No details of the component internals
are reflected in the deployment CMakeLists.txt file.

Test components
'''''''''''''''

Test code is treated in exactly the same as any other source code and is organized into components to achieve
the same reuse goals.  To create a deployment intended for testing, you select an appropriate set of components
where some happen to be test components.  By convention, test components live in sub-directories called test.
Test directories are located at the point in the components sub-tree that reflects the scope of tests.  In the
above example, two test sub-directories are illustrated.  The locations of the test component directories imply
the following about the scope of the tests::

    components
        |-- service
        |   |-- common
        |   |       |-- test        <-- Tests for the common service component
        |   |-- secure-storage
        |   |       |-- frontend
        |   |       |-- backend
        |   |       |-- factory
        |   |       |-- test        <-- Service level tests for the secure-storage service

If it is necessary to componentize tests further, sub-directories under the test directory may be used, say
for different classes of test. e.g::

    components
        |-- service
            |-- common
                    |-- test
                        |-- unit
                        |-- fuzz

external
''''''''

Code that originates from other open source projects that needs to be built as part of trusted service
deployments is represented by directories beneath the external top-level directory.  External components
are generally fetched from the source repo during the CMake build process.  During the build for a particular
deployment, a deployment specific configuration may be applied to an external component.   A CMake file under
each external component directory is responsible for fetching and building the external component::

    external
        |-- CppUTest
        |       |-- CppUTest.cmake
        |       |-- cpputest-cmake-fix.patch
        |-- mbed-crypto
        |-- nanopb

protocols
'''''''''

The protocols directory holds protocol definition files to allow clients to use trusted services.  Ideally,
the service access protocol should be formally defined using an interface description language (IDL) that
provides a programming language neutral definition of the service interface.  The protocols directory
structure accommodates protocol definitions using different definition methods.  Where a service access
protocol has been defined using an IDL with language compilation support, code may be generated from the
interface description to allow RPC request and response parameters to be serialized and deserialized in a
compatible way between service clients and providers.  The protocols sub-tree is organized as follows::

    protocols
        |-- service
        |       |-- common
        |       |-- crypto
        |       |       |-- packed-c        <-- C structure based definitions
        |       |       |-- protobuf        <-- Protocol Buffers definitions
        |       |-- secure-storage
        |               |-- packed-c

tools
'''''

The project directory structure includes a tools directory for holding general purpose tools components
to support activities such as build and test.

--------------

*Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
