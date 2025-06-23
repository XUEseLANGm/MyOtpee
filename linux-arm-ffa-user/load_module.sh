#!/bin/sh

[ ! -f $(dirname "$0")/sp_uuid_list.txt ] && \
	{ echo "Error: missing SP UUID list"; exit 1; }

if ! grep -qs 'arm-ffa-user' /proc/modules; then
	insmod $(dirname "$0")/arm-ffa-user.ko uuid_str_list=$(cat $(dirname "$0")/sp_uuid_list.txt)
fi

if ! grep -qs 'debugfs' /proc/mounts; then
	mount -t debugfs debugfs /sys/kernel/debug/
fi
