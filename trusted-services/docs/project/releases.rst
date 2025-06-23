Releases
========

The release is a well documented and identifiable "quality snapshot" of the products the project is developing. It helps
adopters by providing reference points and understanding differences between these.

Due to the :ref:`Version Control` policy implemented, each commit on the "main" branch has a source code and runtime
quality level as a release. The release in addition to that ads extra documentation of changes in form of the
:ref:`Change Log & Release Notes`

Cadence
-------

There is no fixed release cadence defined yet.

Release procedure
=================

``DR`` below stands for "Day of Release".

.. list-table:: Release steps
   :header-rows: 1

   * - Time
     - Task
   * - ``DR``-3w
     -
         - Send notification to |TS_MAIL_LIST| about upcoming release.
         - Release note update starts.
         - Platform maintainers prepare for testing their platforms.
   * - ``DR``-1w
     -
        - A release PR is created updating the release ID and release notes.
        - "integration" branch is frozen and "main" branch is updated if needed.
        - "main" branch is tagged with `_rc0` tag to mark start of release testing.
        - Maintainers start release testing.
        - Platform maintainers start release testing their platforms.
   * - ``DR``
     -
        - Release notes is finalized.
        - Release PR gets merged.
        - "main" branch is updated.
        - "main" branch is tagged.
        - Release announcement is sent to |TS_MAIL_LIST|.

Errors discovered during testing will break the release process. Fixes need to be made and merged as usual, and release
testing to be restarted with including applying a new ``_rc<x>`` tag, where ``<x>`` is a monotonic counter.

If fixing the encountered errors takes long, the release is either aborted and postponed, or the defects are captured in
the release notes under the "known issues" section.

--------------

*Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause