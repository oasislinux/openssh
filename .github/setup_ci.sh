#!/bin/sh

 . .github/configs $@

TARGETS=$@

PACKAGES=""
BEARSSL_BRANCH="v0.6"
export DEBIAN_FRONTEND=noninteractive

#echo "Setting up for '$TARGETS'"

set -ex

case $(./config.guess) in
*-darwin*)
	brew install automake
	cd ${HOME}
	git clone -b v0.6 https://bearssl.org/git/BearSSL bearssl
	cd bearssl
	make -j2
	cp build/libbearssl.a /usr/local/lib
	cp inc/*.h /usr/local/include
	exit 0
	;;
esac

lsb_release -a

if [ "${TARGETS}" = "kitchensink" ]; then
	TARGETS="krb5 libedit pam sk selinux"
fi

for flag in $CONFIGFLAGS; do
    case "$flag" in
    --with-pam)		PACKAGES="${PACKAGES} libpam0g-dev" ;;
    --with-libedit)	PACKAGES="${PACKAGES} libedit-dev" ;;
    esac
done

for TARGET in $TARGETS; do
    case $TARGET in
    default|without-zlib|c89|libedit|*pam)
        # nothing to do
        ;;
    clang-*|gcc-*)
        compiler=$(echo $TARGET | sed 's/-Werror//')
        PACKAGES="$PACKAGES $compiler"
        ;;
    krb5)
        PACKAGES="$PACKAGES libkrb5-dev"
	;;
    heimdal)
        PACKAGES="$PACKAGES heimdal-dev"
        ;;
    sk)
        INSTALL_FIDO_PPA="yes"
        INSTALL_LIBFIDO2="yes"
        PACKAGES="$PACKAGES libu2f-host-dev libcbor-dev"
        ;;
    selinux)
        PACKAGES="$PACKAGES libselinux1-dev selinux-policy-dev"
        ;;
    hardenedmalloc)
        INSTALL_HARDENED_MALLOC=yes
        ;;
    musl)
	PACKAGES="$PACKAGES musl-tools"
	;;
    tcmalloc)
        PACKAGES="$PACKAGES libgoogle-perftools-dev"
        ;;
    bearssl-head)
        BEARSSL_BRANCH="master"
        ;;
    without-bearssl)
        BEARSSL_BRANCH=""
        ;;
    valgrind*)
        PACKAGES="$PACKAGES valgrind"
        ;;
    *) echo "Invalid option '${TARGET}'"
        exit 1
        ;;
    esac
done

if [ "yes" = "$INSTALL_FIDO_PPA" ]; then
    sudo apt update -qq
    sudo apt install -qy software-properties-common
    sudo apt-add-repository -y ppa:yubico/stable
fi

if [ "x" != "x$PACKAGES" ]; then 
    sudo apt update -qq
    sudo apt install -qy $PACKAGES
fi

if [ "${INSTALL_HARDENED_MALLOC}" = "yes" ]; then
    (cd ${HOME} &&
     git clone https://github.com/GrapheneOS/hardened_malloc.git &&
     cd ${HOME}/hardened_malloc &&
     make -j2 && sudo cp out/libhardened_malloc.so /usr/lib/)
fi

if [ "x" != "x$BEARSSL_BRANCH" ]; then
    (cd ${HOME} &&
     git clone -b ${BEARSSL_BRANCH} https://bearssl.org/git/BearSSL bearssl &&
     cd bearssl && make -j2 &&
     sudo cp build/libbearssl.a /usr/local/lib &&
     sudo cp inc/*.h /usr/local/include)
fi

if [ "x$INSTALL_LIBFIDO2" = "xyes" ]; then
    (cd ${HOME} &&
     git clone https://github.com/oasislinux/libfido2.git &&
     cd libfido2 && cmake -DCMAKE_INSTALL_PREFIX=/usr . &&
     make -j2 && sudo make install)
fi
