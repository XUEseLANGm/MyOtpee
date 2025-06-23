Verification Strategy
=====================

This page describes verification from a high level concept perspective.

In this context ``source code`` has a wider scope and may mean any text content produced by humans and processed by
other humans or tools. Examples: C/C++ source code, reST documents, build scripts, etc...

Clean Code
----------

Clean code aims to counterfeit issues discussed in the following sub-chapters.

Code Readability
''''''''''''''''

Expressing ideas in a machine readable formats is complicated, and each developer may have a different taste or
different preferences on how source code should be formatted. Some people may find a specific kind of formatting easier
to understand than others. If the source code does not follow a consistent look and feel, human processing of the text
may become error prone. This undermines effectiveness of co-operation and code-review, and may lead to incorrect code.
The project defines coding style rules to counterfeit these problems. For detail please refer to :ref:`Coding Style &
Guidelines`

Undefined and Implementation Defined Behavior
'''''''''''''''''''''''''''''''''''''''''''''

The "standard" defining how to process a specific source code type, may leave some processing behavior to the tool
to be defined, or allow the tool to behave in an undefined way. Coding constructs relying on such behavior are to be
avoided, or used in a well defined way. This adds robustness and helps avoiding errors due to using different version
of the same tool, or different implementations.

The project defines coding guidelines to counterfeit these problems. For detail please refer to
:ref:`Coding Style & Guidelines`

Security
''''''''

Security is a complex topic affecting all steps of the development process. Incorrect code may lead to security issues
and thus "Clean Code" has a vital role in implementing secure software.

Runtime Testing
---------------

Runtime testing focuses of verifying the behavior of one or multiple build products built from source code. This can be
done at multiple levels and in multiple execution environment.


Unit Test
'''''''''

Unit tests aim to verify if the internal operation of a module matches the developers expectation. It helps covering all
code execution paths, and to give confidence on correct operation when code needs to be refactored. Unit tests serve as
a kind of documentation capturing the expected usage of the code.

Unit-testing allays happen on the "host PC"

Component Test
''''''''''''''

Component tests aim to verify the API (and ABI) of a component is matching expectations. Components are tested in
isolation, where the exported APIs are exercised by these code, and APIs the component depends on are implemented by
test doubles.

System Test
'''''''''''

System test verifies correct operation of a set of modules configured to fulfill the requirements of a use-case. For TS
this usually means testing and end-to-end setup on a specific target platform.

Balancing Costs vs Quality
''''''''''''''''''''''''''

Executing build products on target platforms may have high costs in terms of time, complexity and availability and in
turn it gives the hights confidence in verification results, or the best quality. In the development phase it may be
desired to some level of this confidence for lower costs. For this purpose the project defines two main test
set-up types based on the balance choice between cost and quality.

Testing on a Target Platform
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this environment tests are executed on a target platform. Emulators (e.g. QEMU, FVP) from this aspect are treated
like targets implemented in silicon.

Testing on the Host Machine
~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this environment test executables are compiled to execute as a "standard" user-space application running on the
machine "hosting" the development activity. In most cases these machines are based on a different architecture that the
ones the project is targeting (e.g. x86-64 vs aarch64). This means this environment relies on the assumption that code
is portable and behaves architecture and compiler independent. This puts limitations on the features which can be tested
and lower the confidence level of test output. In turn executing tests int his environment is simple and gives very good
scalability options.

--------------

*Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause