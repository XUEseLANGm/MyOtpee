Build test runner
=================

This directory captures build test case definitions and a tool to execute the test based on
the data. The tool combines the power of shell scripting with the power of structured data
(|yaml|). The bridge between the two technologies is provided by |jinja2| template engine
and |yasha|.

Dependencies
------------

|Jinja2| and |yasha| are python tools and python3 is needed to run the tests. Please install
the following tools into your build environment:

   - python3
   - pip3

After this please install further pip packages listed in ``requirements.txt`` as:

.. code:: shell

    pip3 install -r requirements.txt

.. note::

    This document lists the dependencies of this tool only. To be able to successfully run the
    build tests further tools are needed. Please refer to the ``Trusted Services``
    documentation for details.

Files
-------

.. uml::

    @startsalt
    {
    {T
        + b-test
        ++Makefile                 | generate and run tests
        ++Readme.rst               | this document
        ++requirements.txt         | pip package dependencies
        ++run.sh.j2                | shell script template
        ++test_data.schema.json    | JSON schema for test case data
        ++test_data.yaml           | test case data
        ++//user.env//             | optional user specific settings
    }
    }
    @endsalt

Design
------

The project needs a convenient way to define and execute "build tests". This test aims to ensure
all build configurations are in a good working condition. Testing is done by executing build
of all supported build configurations. In order to make the testing robust and easy to use a
"data driven" approach is the best fit. With this test cases are described by pure data and this
data is processed by some tool which is responsible for test execution.

For command execution the bash shell is a good candidate. It provides portability between OSs, is
widely adopted and well tested. Unfortunately shells are not good on handling structured data.
To address this shortcoming templating is utilized or "code generation" is used. The shell script
to execute the command is generated based on a template file and the test data.

Since python is already a dependency of Trusted Services we selected the |Jinja2| template engine
to go with, and to decrease maintenance cost, we use it trough |yasha|.

.. uml::

    @startuml
    [test_data.yaml] --> [yasha]
    [run.sh.j2] --> [yasha]
    [//user.env//] -right-> [run.sh]
    [yasha] --> [run.sh]
    @enduml

Usage
-----

There are two "entry points" to the tests. If the intention is to run all tests, issue ``make``.

Makefile
""""""""
The makefile is responsible to provide a high level "API". It allows executing the script generation
process and to run the tests. It ensures all components are fresh before being executed.

Issue ``make help`` to get a list of supported commands.

run.sh
""""""

``run.sh`` is the test runner. It is responsible to execute the needed builds in a proper way and
thus validate the build definitions.

Execute ``run.sh help`` to get further details.


--------------

.. |yasha| replace:: `yasha`_
.. |jinja2| replace:: `Jinja2`_
.. |yaml| replace:: `yaml`_

.. _Jinja2: https://palletsprojects.com/p/jinja
.. _yasha: https://github.com/kblomqvist/yasha
.. _yaml: https://yaml.org

*Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause