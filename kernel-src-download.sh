#!/bin/bash
# get-verified-tarball
# --------------------
# Get Linux kernel tarball and cryptographically verify it,
# retrieving the PGP keys using the Web Key Directory (WKD)
# protocol if they are not already in the keyring.
#
# Pass the kernel version as the only parameter, or
# we'll grab the latest stable kernel.
#
# Example: ./get-verified-tarball 4.4.145

source "$(dirname "$(readlink -f "$0")")/env.sh"

# Configurable parameters
# -----------------------
# Where to download the tarball and verification data.
TARGETDIR=${BMCCACHE_BASE_PATH}

# What kernel version do you want?
VER=${BMCCACHE_KERNEL_VERSION}

# If you set this to empty value, we'll make a temporary
# directory and fetch the verification keys from the
# Web Key Directory each time. Also, see the USEKEYRING=
# configuration option for an alternative that doesn't
# rely on WKD.
GNUPGHOME=

# For CI and other automated infrastructure, you may want to
# create a keyring containing the keys belonging to:
#  - autosigner@kernel.org
#  - torvalds@kernel.org
#  - gregkh@kernel.org
#
# To generate the keyring with these keys, do:
#   gpg --export autosigner@ torvalds@ gregkh@ > keyring.gpg
#   (or use full keyids for maximum certainty)
#
# Once you have keyring.gpg, install it on your CI system and set
# USEKEYRING to the full path to it. If unset, we generate our own
# from GNUPGHOME.
USEKEYRING=

# Point this at your GnuPG binary version 2.1.11 or above.
# If you are using USEKEYRING, GnuPG-1 will work, too.
GPGBIN="/usr/bin/gpg"
GPGVBIN="/usr/bin/gpgv"
# We need a compatible version of sha256sum, too
SHA256SUMBIN="/usr/bin/sha256sum"
# And curl
CURLBIN="/usr/bin/curl"
# And we need the xz binary
XZBIN="/usr/bin/xz"

# You shouldn't need to modify this, unless someone
# other than Linus or Greg start releasing kernels.
DEVKEYS="torvalds@kernel.org gregkh@kernel.org"
# Don't add this to DEVKEYS, as it plays a wholly
# different role and is NOT a key that should be used
# to verify kernel tarball signatures (just the checksums).
SHAKEYS="autosigner@kernel.org"

if [[ -z ${VER} ]]; then
    # Assume you want the latest stable
    VER=$(${CURLBIN} -sL https://www.kernel.org/finger_banner \
          | grep 'latest stable version' \
          | awk -F: '{gsub(/ /,"", $0); print $2}')
fi
if [[ -z ${VER} ]]; then
    echo "Could not figure out the latest stable version."
    exit 1
fi

MAJOR="$(echo ${VER} | cut -d. -f1)"
if [[ ${MAJOR} -lt 3 ]]; then
    echo "This script only supports kernel v3.x.x and above"
    exit 1
fi

if [[ ! -d ${TARGETDIR} ]]; then
    echo "${TARGETDIR} does not exist"
    exit 1
fi

TARGET="${TARGETDIR}/linux-${VER}.tar.xz"
# Do we already have this file?
if [[ -f ${TARGET} ]]; then
    echo "File ${TARGETDIR}/linux-${VER}.tar.xz already exists."
    exit 0
fi

# Start by making sure our GnuPG environment is sane
if [[ ! -x ${GPGBIN} ]]; then
    echo "Could not find gpg in ${GPGBIN}"
    exit 1
fi
if [[ ! -x ${GPGVBIN} ]]; then
    echo "Could not find gpgv in ${GPGVBIN}"
    exit 1
fi

# Let's make a safe temporary directory for intermediates
TMPDIR=$(mktemp -d ${TARGETDIR}/linux-tarball-verify.XXXXXXXXX.untrusted)
echo "Using TMPDIR=${TMPDIR}"
# Are we using a keyring?
if [[ -z ${USEKEYRING} ]]; then
    if [[ -z ${GNUPGHOME} ]]; then
        GNUPGHOME="${TMPDIR}/gnupg"
    elif [[ ! -d ${GNUPGHOME} ]]; then
        echo "GNUPGHOME directory ${GNUPGHOME} does not exist"
        echo -n "Create it? [Y/n]"
        read YN
        if [[ ${YN} == 'n' ]]; then
            echo "Exiting"
            rm -rf ${TMPDIR}
            exit 1
        fi
    fi
    mkdir -p -m 0700 ${GNUPGHOME}
    echo "Making sure we have all the necessary keys"
    ${GPGBIN} --batch --quiet \
        --homedir ${GNUPGHOME} \
        --auto-key-locate wkd \
        --locate-keys ${DEVKEYS} ${SHAKEYS}
    # If this returned non-0, we bail
    if [[ $? != "0" ]]; then
        echo "Something went wrong fetching keys"
        rm -rf ${TMPDIR}
        exit 1
    fi
    # Make a temporary keyring and set USEKEYRING to it
    USEKEYRING=${TMPDIR}/keyring.gpg
    ${GPGBIN} --batch \
        --homedir ${GNUPGHOME} \
        --export ${DEVKEYS} ${SHAKEYS} > ${USEKEYRING}
fi
# Now we make two keyrings -- one for the autosigner, and
# the other for kernel developers. We do this in order to
# make sure that we never verify kernel tarballs using the
# autosigner keys, only using developer keys.
SHAKEYRING=${TMPDIR}/shakeyring.gpg
${GPGBIN} --batch \
    --no-default-keyring --keyring ${USEKEYRING} \
    --export ${SHAKEYS} > ${SHAKEYRING}
DEVKEYRING=${TMPDIR}/devkeyring.gpg
${GPGBIN} --batch \
    --no-default-keyring --keyring ${USEKEYRING} \
    --export ${DEVKEYS} > ${DEVKEYRING}

# Now that we know we can verify them, grab the contents
TXZ="https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${VER}.tar.xz"
SIG="https://cdn.kernel.org/pub/linux/kernel/v${MAJOR}.x/linux-${VER}.tar.sign"
SHA="https://www.kernel.org/pub/linux/kernel/v${MAJOR}.x/sha256sums.asc"

# Before we verify the developer signature, we make sure that the
# tarball matches what is on the kernel.org master. This avoids
# CDN cache poisoning that could, in theory, use vulnerabilities in
# the XZ binary to alter the verification process or compromise the
# system performing the verification.
SHAFILE=${TMPDIR}/sha256sums.asc
echo "Downloading the checksums file for linux-${VER}"
if ! ${CURLBIN} -sL -o ${SHAFILE} ${SHA}; then
    echo "Failed to download the checksums file"
    rm -rf ${TMPDIR}
    exit 1
fi
echo "Verifying the checksums file"
COUNT=$(${GPGVBIN} --keyring=${SHAKEYRING} --status-fd=1 ${SHAFILE} \
        | grep -c -E '^\[GNUPG:\] (GOODSIG|VALIDSIG)')
if [[ ${COUNT} -lt 2 ]]; then
    echo "FAILED to verify the sha256sums.asc file."
    rm -rf ${TMPDIR}
    exit 1
fi
# Grab only the tarball we want from the full list
SHACHECK=${TMPDIR}/sha256sums.txt
grep "linux-${VER}.tar.xz" ${SHAFILE} > ${SHACHECK}

echo
echo "Downloading the signature file for linux-${VER}"
SIGFILE=${TMPDIR}/linux-${VER}.tar.asc
if ! ${CURLBIN} -sL -o ${SIGFILE} ${SIG}; then
    echo "Failed to download the signature file"
    rm -rf ${TMPDIR}
    exit 1
fi
echo "Downloading the XZ tarball for linux-${VER}"
TXZFILE=${TMPDIR}/linux-${VER}.tar.xz
if ! ${CURLBIN} -L -o ${TXZFILE} ${TXZ}; then
    echo "Failed to download the tarball"
    rm -rf ${TMPDIR}
    exit 1
fi

pushd ${TMPDIR} >/dev/null
echo "Verifying checksum on linux-${VER}.tar.xz"
if ! ${SHA256SUMBIN} -c ${SHACHECK}; then
    echo "FAILED to verify the downloaded tarball checksum"
    popd >/dev/null
    rm -rf ${TMPDIR}
    exit 1
fi
popd >/dev/null

echo
echo "Verifying developer signature on the tarball"
COUNT=$(${XZBIN} -cd ${TXZFILE} \
        | ${GPGVBIN} --keyring=${DEVKEYRING} --status-fd=1 ${SIGFILE} - \
        | grep -c -E '^\[GNUPG:\] (GOODSIG|VALIDSIG)')
if [[ ${COUNT} -lt 2 ]]; then
    echo "FAILED to verify the tarball!"
    rm -rf ${TMPDIR}
    exit 1
fi
mv -f ${TXZFILE} ${TARGET}
rm -rf ${TMPDIR}
echo
echo "Successfully downloaded and verified ${TARGET}"
