# Copyright (c) 2020-2023, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

.SUFFIXES:
.SUFFIXES: .j2

# Disable parallel execution for this makefile.
.NOTPARALLEL:

TEMPLATES:=$(wildcard *.j2)
OUTPUTS:=$(TEMPLATES:%.j2=%)

FILTER_PATTERN ?=

ifneq (,${FILTER_PATTERN})
RUN_SH_ARGS += -p "${FILTER_PATTERN}"
endif

ifneq (,${INSTALL_PREFIX})
RUN_SH_ARGS += -i ${INSTALL_PREFIX}
endif

ifneq (,${BUILD_PREFIX})
RUN_SH_ARGS += -b ${BUILD_PREFIX}
endif

ifneq (,${LOGDIR_ROOT})
RUN_SH_ARGS += -l ${LOGDIR_ROOT}
endif

all:
	${MAKE} config
	bash run.sh ${RUN_SH_ARGS}

config: ${OUTPUTS}

list:
	${MAKE} config
	bash run.sh ${RUN_SH_ARGS} help

# run a command of the generated script
r-%:
	${MAKE} config
	bash run.sh ${RUN_SH_ARGS} "$*"

define help_msg
*************************************************************
Variables:
  Variables can be passed as arguments (make <var>=<value>)
  or be set in the environment (e.g. export <var>=<value>;
  make ...).

  BUILD_PREFIX   - Directory for build directories
  FILTER_PATTERN - grep regexp to limit test scope to tests
                   whose name matches. To see the selected tests
                   run: make FILTER_PATTERN=<pattern> list
  INSTALL_PREFIX - Directory to install projects
  LOGDIR_ROOT    - Directory to save build logs

Available targets:
  all          - generate and run test script
  config       - run script generation only
  clean        - remove intermediate files
  list         - run config and list test cases
  p-<variable> - print value of make variable (for debugging)
  r-<test>     - run a command of the generated script. Allow
                 executing a single test case. Use
                    make r-help
                 to get the list of tests.
*************************************************************
endef

export help_msg
help:
	@echo "$$help_msg"

# remove intermediate output
clean:
ifneq ($(wildcard ./run.sh),)
	bash run.sh clean
endif
	-rm -rf ${OUTPUTS}

# Convert template to shell script
%.sh : %.sh.j2 test_data.yaml
	yasha -v test_data.yaml $<

# print variable value (i.e. make p-TEMPLATES)
p-%:
	@echo $*=${$*}
