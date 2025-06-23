Version Control
===============

Version control is about tracking and managing changes to text files including source-code, scripts, configuration
files and documentation.

The project uses the `Git version control system`_ and Gerrit as the code review and access restriction enforcement
solution. Although git is a distributed version control system the project uses a "centralized" approach. The main
repositories can be found at https://trustedfirmware.org, where two WEB UIs can be found:

    - a `cgit instance`_ allowing browse and clone the repositories
    - and a `Gerrit instance`_ for contribution and code review purposes.

Currently the project has a single repository hosting the source-code:
https://git.trustedfirmware.org/TS/trusted-services.git/

Branching Strategy
------------------

The branching strategy is built around a "quality" based flow of changes.

Each change starts targeting an "integration" branch either as a "standalone" change or as a topic. Changes landing on
integrations are expected to be "independent" (properly build and working without depending on other changes).
Validation efforts of the changes my have limited focus based on the expected effect of the change. This allows
balancing validation costs to pay during reviews.

All change landing on the integration branch will get trough full validation. When passing all quality checks, the
change can be merged to a "main" branch. All changes on the main branch are expected to fulfill all quality requirements
and to pass full validation.

The default name of the "integration" branch is ``integration`` and the default name of the "main" branch is ``main``.
For special purposes (e.g. long term support, hosting a special version, etc...) other branches acting as "integration"
and "main" can be defined.

Sandbox branches
----------------

For prototyping purposes the project allows using "sandbox" branches. Changes on these branches are free to lower
quality expectations as needed. Sandbox branches are to be created under ``sandbox/<username>/`` namespace
(e.g. ``sandbox/gyoszi01/static-init-prototype``).

Topic branches
--------------

For large changes or changes expected to have a longer development time "topic" branches can be used. Topic branches are
to be created under the ``topics/<username>/<some name>`` namespace. If multiple developers are co-developing a feature
``<username>`` is expect to be the lead developer.

Review vs quality
-----------------

As discussed above all commits on the "integration" branch must properly build and work independent of other changes.
This may result in large commits, which would make code reviews difficult. To help the code review, large changes should
be split to small steps, each implementing a single logical step needed for the full change. To remove the conflict
between quality expectation requiring large and review requiring small commits, topic branches shall be used. Large
changes are to be split up to small steps and target a topic branch first. This way reviewers can check small changes,
and only the tip of the topic branch is to pass build and runtime tests.

.. _`cgit instance`: https://git.trustedfirmware.org/
.. _`Gerrit instance`: https://review.trustedfirmware.org/

-------------

.. _`Git version control system`: https://git-scm.com/

*Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause