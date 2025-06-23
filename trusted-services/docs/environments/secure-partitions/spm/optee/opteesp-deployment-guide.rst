Deploying trusted services in S-EL0 Secure Partitions under OP-TEE
==================================================================

Trusted services built for the *opteesp* environment may be deployed to run within S-EL0 secure
partitions, managed by OP-TEE. The current implementation of the OP-TEE SPMC supports booting SPs
embedded into the OP-TEE OS binary (similar to early-TAs) or from the FIP.

Tool prerequisites and general build instruction for OP-TEE are described here:
`<https://optee.readthedocs.io/en/latest/building/gits/build.html>`_

Download page for Arm Fixed Virtual Platforms (FVP):
`<https://developer.arm.com/tools-and-software/simulation-models/fixed-virtual-platforms>`_


Embedding SP images into the *OP-TEE OS* image
----------------------------------------------

The set of SP images to include in the built *OP-TEE OS* image are specified to the *OP-TEE OS*
build by the ``SP_PATHS`` make variable.  The ``SP_PATHS`` variable should be assigned a string
containing a space separated list of file paths for each SP image file to include. SP images
that need to be deployed from the Trusted Services project will be located in the install directory,
specified when the SP images where built i.e.::

    <CMAKE_INSTALL_PREFIX>/opteesp/bin

The following example illustrates a setting of the ``SP_PATHS`` variable to deploy the Secure Storage
SP and Crypto SP::

    SP_PATHS="ts-install-dir/opteesp/bin/dc1eef48-b17a-4ccf-ac8b-dfcff7711b14.stripped.elf \
        ts-install-dir/opteesp/bin/d9df52d5-16a2-4bb2-9aa4-d26d3b84e8c0.stripped.elf"


Reference OP-TEE build with PSA RoT Services
--------------------------------------------

To provide an example integration of OP-TEE with a set of trusted services, a makefile called
*fvp-ps-sp.mk* is included in the OP-TEE build repository that builds OP-TEE OS with a set of SP
images. SP images are built using the standard trusted services build flow and are automatically
injected into the *optee_os* build using the TA feature described above.

A bootable Linux image is created that is intended to run on the Arm AEM FVP virtual platform. The
built image includes user space programs that may be used to test and demonstrate the deployed
trusted services.


Getting build dependencies
''''''''''''''''''''''''''

To help setup the workspace, a manifest file called *fvp-ts.xml* is included in OP-TEE manifests
repository.  This may be used with the *repo* tool to manage the set of git repositories.

Having created a new directory for the workspace, the required set of git repositories can be cloned
and fetched using::

    repo init -u https://github.com/OP-TEE/manifest.git -b master -m fvp-ts.xml
    repo sync


Building the reference OP-TEE image
'''''''''''''''''''''''''''''''''''

To build the bootable image that includes OP-TEE and the set of secure partition images that hold the
PSA RoT services, use the following (from the root directory of the workspace)::

    make -C build

This will take many tens of minutes to complete.


Running the reference OP-TEE image on FVP
'''''''''''''''''''''''''''''''''''''''''

The fvp makefile includes a *run* and *run-only* target which can be used to start the FVP model and
boot the built image.  The example assumes that the FVP model has been installed in the following
directory relative to the OP-TEE build directory::

    ../Base_RevC_AEMvA_pkg/models/Linux64_GCC-9.3

To boot the built image on FVP without building, use::

    FVP_PATH=../Base_RevC_AEMvA_pkg/models/Linux64_GCC-9.3 make run-only

For information on running user space programs on FVP, see:

:ref:`Running User-space Programs on FVP`

--------------

*Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
