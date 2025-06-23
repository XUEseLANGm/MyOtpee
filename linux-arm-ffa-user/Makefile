# SPDX-License-Identifier: GPL-2.0-only

ARCH			:= arm64
CROSS_COMPILE		?= aarch64-linux-gnu-

ROOT			?= $(CURDIR)/..
KDIR			?= $(ROOT)/linux
TARGET_DIR		?= $(ROOT)/shared

all: module
clean: module-clean

install: module
	cp $(CURDIR)/arm-ffa-user.ko $(TARGET_DIR)/
	cp load_module.sh $(TARGET_DIR)/

module:
	ARCH=$(ARCH) CROSS_COMPILE="$(CROSS_COMPILE)" $(MAKE) -C $(KDIR) M=$(CURDIR) modules

module-clean:
	ARCH=$(ARCH) CROSS_COMPILE="$(CROSS_COMPILE)" $(MAKE) -C $(KDIR) M=$(CURDIR) clean
