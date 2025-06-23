Coding Style & Guidelines
=========================

The following sections contain |TS| coding guidelines for different types of file. They are continually evolving
and should not be considered "set in stone". Feel free to question them and provide feedback.

To help configuring text editors the project comes with "`EditorConfig`_" file(s). (:download:`../../.editorconfig`).

Common Rules
------------

The following rules are common for all types of text file, except where noted otherwise:

#. Files shall be **UTF-8** encoded.
#. Use **Unix** style line endings (``LF`` character)
#. The primary language of the project is English. All comments and documentation must be in this language.
#. Trailing whitespace is not welcome, please trim these.

C Rules
-------

C source code rules are base on the *Linux Coding Style* (See: |LCS|). The following deviations apply:

5. |TS| follows *ISO/IEC 9899:1999* standard with |ACLE| version *Q3 2020* extensions.
#. Line length shall not exceed 100 characters.
#. Use `snake_case`_ for function, variable and file names.
#. Each file shall be "self contained" and include header files with external dependencies. No file shall depend on
   headers included by other files.
#. Include ordering: please include project specific headers first and then system includes. Please order the files
   alphabetically in the above two groups.
#. All variables must be initialized.

C source files should include a copyright and license comment block at the head of each file. Here is an example::

   /*
    * Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
    *
    * SPDX-License-Identifier: BSD-3-Clause
    */

Boring stuff is not for smart people and the project uses the `Clang-Format`_ code beautifier to easy formatting the
source. (See :download:`../../.clang-format`)

CMake Rules
-----------

Cmake files (e.g. CMakeLists.txt and .cmake) should conform to the following rules:

1.  CMake file names use `CamelCase`_ style.
#. Indent with tabs and otherwise use spaces. Use 4 spaces for tab size.
#. Use LF as line end in CMake files.
#. Remove trailing whitespace.
#. Maximum line length is 128 characters.
#. When complicated functionality is needed prefer CMake scripting over other languages.
#. Prefix local variables with `_`.
#. Use functions to prevent global name-space pollution.
#. Use `snake_case`_ for function and variable names.
#. Use the ``include_guard()`` CMake function when creating new modules, to prevent multiple inclusion.
#. Use self contained modules, i.e. include direct dependencies of the module.
#. Use the Sphinx CMake domain for in-line documentation of CMake scripts. For details please refer to the
   `CMake Documentation`_.

Each file should include a copyright and license comment block at the head of each file. Here is an example::

   #-------------------------------------------------------------------------------
   # Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
   #
   # SPDX-License-Identifier: BSD-3-Clause
   #
   #-------------------------------------------------------------------------------

Restructured Text Rules
-----------------------

Please refer to :doc:`/developer/writing-documentation`.

--------------

.. _`CamelCase`: https://hu.wikipedia.org/wiki/CamelCase
.. _`snake_case`: https://en.wikipedia.org/wiki/Snake_case
.. _`CMake Documentation`: https://github.com/Kitware/CMake/blob/master/Help/dev/documentation.rst
.. _`EditorConfig`: https://editorconfig.org/
.. _`Clang-Format`: https://clang.llvm.org/docs/ClangFormat.html

*Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
