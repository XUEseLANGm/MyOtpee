Verification Plan
=================

This document describes when and by whom verification steps are to be executed. Since this is an open-source project
maintained by an open community, each contributor is expected to participate.

Verification during development
-------------------------------

When changing existing code, or adding new code, the developer is expected to:

  - run static checks to guard "clean code".
  - execute runtime tests on the host machine to ensure features not changed are behaving as before. Verification
    efforts targeting regression may be limited based on the expected effects of the change.
  - extend unit and component tests to cover changes

Verification during code review
-------------------------------

The code review covers all aspects of a change, including design and implementation. This includes running static checks
and runtime tests. The reviewers are expected to check if tests are extended as needed.

Verification efforts of a review may be limited to lower costs, based on the expected effects of the change.

Guarding "main"
---------------

All commits of the integration branch shall be verified using the full verification set-up. This verification shall aim
for achieving the highest quality level and shall not make compromises. A change becomes ready to get merged to "main"
after passing the tests.


--------------

*Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause