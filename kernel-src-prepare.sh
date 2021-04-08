#!/bin/bash
# --------------------
# Run this script to extract and generate kernel sources files required to compile BMC
# --------------------
source "$(dirname "$(readlink -f "$0")")/env.sh"

echo "Extracting kernel sources to ${BMCCACHE_BMC_PATH}/linux"
if tar xf ${BMCCACHE_KERNEL_TARXZ} -C ${BMCCACHE_BMC_PATH} && mv ${BMCCACHE_BMC_PATH}/linux-${BMCCACHE_KERNEL_VERSION} ${BMCCACHE_BMC_PATH}/linux; then
	echo "Successfully extracted kernel sources to ${BMCCACHE_BMC_PATH}/linux"
else
	echo "Failed to extract kernel sources"
	exit 1
fi

echo "Preparing kernel sources"
if make -C ${BMCCACHE_BMC_PATH}/linux defconfig && make -C ${BMCCACHE_BMC_PATH}/linux prepare; then
	echo "Done preparing kernel sources"
else
	echo "Failed to prepare kernel sources"
	exit 1
fi
