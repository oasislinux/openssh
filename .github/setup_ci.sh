#!/bin/sh

PACKAGES=""

 . .github/configs $@

case "`./config.guess`" in
*cygwin)
	PACKAGER=setup
	echo Setting CYGWIN system environment variable.
	setx CYGWIN "binmode"
	echo Removing extended ACLs so umask works as expected.
	setfacl -b . regress
	PACKAGES="$PACKAGES,autoconf,automake,cygwin-devel,gcc-core"
	PACKAGES="$PACKAGES,make,zlib-devel"
	;;
*-darwin*)
	PACKAGER=brew
	brew install automake
	;;
*)
	PACKAGER=apt
esac

TARGETS=$@

INSTALL_BEARSSL="v0.6"
INSTALL_FIDO_PPA="no"
INSTALL_LIBFIDO2="no"
export DEBIAN_FRONTEND=noninteractive

#echo "Setting up for '$TARGETS'"

set -ex

if [ -x "`which lsb_release 2>&1`" ]; then
	lsb_release -a
fi

# Ubuntu 22.04 defaults to private home dirs which prevent the
# agent-getpeerid test from running ssh-add as nobody.  See
# https://github.com/actions/runner-images/issues/6106
if [ ! -z "$SUDO" ] && ! "$SUDO" -u nobody test -x ~; then
	echo ~ is not executable by nobody, adding perms.
	chmod go+x ~
fi

if [ "${TARGETS}" = "kitchensink" ]; then
	TARGETS="krb5 libedit pam sk selinux"
fi

for flag in $CONFIGFLAGS; do
    case "$flag" in
    --with-pam)		TARGETS="${TARGETS} pam" ;;
    --with-libedit)	TARGETS="${TARGETS} libedit" ;;
    esac
done

for TARGET in $TARGETS; do
    case $TARGET in
    default|without-zlib|c89)
        # nothing to do
        ;;
    clang-sanitize*)
        PACKAGES="$PACKAGES clang-12"
        ;;
    cygwin-release)
        PACKAGES="$PACKAGES libcrypt-devel libfido2-devel libkrb5-devel"
        ;;
    gcc-sanitize*)
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
    libedit)
	case "$PACKAGER" in
	setup)	PACKAGES="$PACKAGES libedit-devel" ;;
	apt)	PACKAGES="$PACKAGES libedit-dev" ;;
	esac
        ;;
    *pam)
        PACKAGES="$PACKAGES libpam0g-dev"
        ;;
    sk)
        INSTALL_FIDO_PPA="yes"
        INSTALL_LIBFIDO2="yes"
        PACKAGES="$PACKAGES libu2f-host-dev libcbor-dev libudev-dev"
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
        INSTALL_BEARSSL="master"
        ;;
    without-bearssl)
        INSTALL_BEARSSL=""
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

tries=3
while [ ! -z "$PACKAGES" ] && [ "$tries" -gt "0" ]; do
    case "$PACKAGER" in
    apt)
	sudo apt update -qq
	if sudo apt install -qy $PACKAGES; then
		PACKAGES=""
	fi
	;;
    setup)
	if /cygdrive/c/setup.exe -q -P `echo "$PACKAGES" | tr ' ' ,`; then
		PACKAGES=""
	fi
	;;
    esac
    if [ ! -z "$PACKAGES" ]; then
	sleep 90
    fi
    tries=$(($tries - 1))
done
if [ ! -z "$PACKAGES" ]; then
	echo "Package installation failed."
	exit 1
fi

if [ "${INSTALL_HARDENED_MALLOC}" = "yes" ]; then
    (cd ${HOME} &&
     git clone https://github.com/GrapheneOS/hardened_malloc.git &&
     cd ${HOME}/hardened_malloc &&
     make -j2 && sudo cp out/libhardened_malloc.so /usr/lib/)
fi

if [ "x" != "x$INSTALL_BEARSSL" ]; then
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
