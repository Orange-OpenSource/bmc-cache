#!/bin/bash
# --------------------
# Run this script to delete downloaded kernel sources
# --------------------
source "$(dirname "$(readlink -f "$0")")/env.sh"

if [[ -f ${BMCCACHE_KERNEL_TARXZ} ]]; then
    echo "Deleting ${BMCCACHE_KERNEL_TARXZ}"
    rm -rf ${BMCCACHE_KERNEL_TARXZ}
fi

if [[ -d "${BMCCACHE_BMC_PATH}/linux" ]]; then
    echo "Deleting ${BMCCACHE_BMC_PATH}/linux"
    rm -rf "${BMCCACHE_BMC_PATH}/linux"
fi

echo "Finished cleaning up."
