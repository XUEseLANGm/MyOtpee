Project Goals
=============

The trusted services project aims to make it easy to write new trusted services that can be deployed in different secure
processing environments without having to rewrite lots of code.  The aim is to make component reuse as painless as possible by
keeping software components free of unnecessary dependencies on anything environment or platform specific.

The project structure has been designed to help meet the following goals:

    - **Support multiple deployments** - allow for different deployments where common service code can be built to run in
      different environments.
    - **Support multiple processing environments** - allow support for new processing environments to be easily added.
    - **Support multiple hardware platforms** - provide a portability model for different hardware.
    - **Avoid the need for duplicated code** - by encouraging code sharing, code duplication can be minimized.
    - **Avoid cross-talk between builds** - allow images for different deployments to be built independently without any nasty
      cross dependencies.
    - **Support and promote automated testing** - writing and running test cases that operate on individual components,
      component assemblies or complete service deployments should be easy and accessible.
    - **Support component sharing with deployment specific configuration** - where necessary, a deployment specific build
      configuration may need to be applied to a shared component.
    - **Control which versions of external components are used** - where external components such as libraries are used, it
      should be possible to peg to a specific version.

Enhancing Security through Reuse and Testing
--------------------------------------------

Reuse of common framework and service components across multiple deployments will help to shake out bugs that may present
security vulnerabilities.  Repeated reuse of a piece of software in different contexts and by different people can help harden
the code through progressive improvements and bug fixes.  Reuse of a common framework also creates opportunities for standard
solutions to security problems such as service discovery, client identification, authentication and access control.

The confidence to reuse components needs to be underpinned by testing.  A project structure that makes it easy to add tests, run
tests and live with an increasing suite of test cases is fundamentally important in meeting security goals.  Although trusted
service code will be deployed in execution environments where test and debug can be somewhat awkward, a large amount of the code
can be tested effectively in a native PC environment.  Where code can be tested on a PC, it should be.  It should be easy for
anyone to build and run tests to give confidence that a component passes all tests before changes are made and that code changes
haven't broken anything.

----------------

*Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
