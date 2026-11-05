#!/bin/sh

config="$1"
target="$2"

PACKAGES="tmux"

echo Running as:
id

echo Saving environment to runner-env.txt
set >runner-env.txt

 . .github/configs ${config}

host=`./config.guess`
echo "config.guess: $host"
case "$host" in
*cygwin)
	PACKAGER=setup
	echo Setting CYGWIN system environment variable.
	setx CYGWIN "winsymlinks:native"
	echo Removing extended ACLs on regress so umask works as expected.
	echo "Original ACLs"
	icacls regress
	setfacl -b regress
	icacls regress /c /t /q /grant 'BUILTIN\Administrators:(RX)'
	echo "Modifiled ACLs"
	icacls regress

	echo Enabling OpenSSL rh-allow-sha1-signatures for unit tests.
	cp /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.bak
	cat >>/etc/pki/tls/openssl.cnf <<EOD
[openssl_init]
alg_section = evp_properties

[evp_properties]
rh-allow-sha1-signatures = yes
EOD
	openssl list -providers -provider legacy
	printf "Test openssl signing with RSA+SHA1: "
	openssl genpkey -quiet -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
	openssl pkey -in private_key.pem -pubout -out public_key.pem
	if ! openssl dgst -sha1 -sign private_key.pem -out signature.sig public_key.pem; then
		echo fail
		echo "openssl could not sign with RSA+SHA1."
		cp /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.bak regress/
		exit 1
	else
		echo success
	fi

	PACKAGES="$PACKAGES,autoconf,automake,cygwin-devel,gcc-core"
	PACKAGES="$PACKAGES,make,zlib-devel"
	;;
*-darwin*)
	PACKAGER=brew
	PACKAGES="automake"
	;;
*)
	PACKAGER=apt
esac

TARGETS=${config}

INSTALL_BEARSSL="v0.6"
INSTALL_FIDO_PPA="no"
export DEBIAN_FRONTEND=noninteractive

set -e

if [ -x "`which lsb_release 2>&1`" ]; then
	lsb_release -a
fi

if [ ! -z "$SUDO" ]; then
	# Ubuntu 22.04 defaults to private home dirs which prevent the
	# agent-getpeerid test from running ssh-add as nobody.  See
	# https://github.com/actions/runner-images/issues/6106
	if ! "$SUDO" -u nobody test -x ~; then
		echo ~ is not executable by nobody, adding perms.
		chmod go+x ~
	fi
	# Some of the Mac OS X runners don't have a nopasswd sudo rule. Regular
	# sudo still works, but sudo -u doesn't.  Restore the sudo rule.
	if ! "$SUDO" grep  -E 'runner.*NOPASSWD' /etc/passwd >/dev/null; then
		echo "Restoring runner nopasswd rule to sudoers."
		echo 'runner ALL=(ALL) NOPASSWD: ALL' |$SUDO tee -a /etc/sudoers
	fi
	if ! "$SUDO" -u nobody -S test -x ~ </dev/null; then
		echo "Still can't sudo to nobody."
		exit 1
	fi
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

echo "Setting up for '$TARGETS'"
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
	PACKAGES="$PACKAGES libkrb5-dev libnss-wrapper krb5-admin-server"
	;;
    heimdal)
	PACKAGES="$PACKAGES heimdal-dev libnss-wrapper krb5-admin-server"
	;;
    libedit)
	case "$PACKAGER" in
	setup)	PACKAGES="$PACKAGES libedit-devel" ;;
	apt)	PACKAGES="$PACKAGES libedit-dev" ;;
	esac
	;;
    *pam)
	case "$PACKAGER" in
	apt)	PACKAGES="$PACKAGES libpam0g-dev" ;;
	esac
	;;
    sk)
	INSTALL_FIDO_PPA="yes"
	INSTALL_LIBFIDO2="yes"
	PACKAGES="$PACKAGES libu2f-host-dev libcbor-dev libudev-dev"
	;;
    selinux)
	PACKAGES="$PACKAGES libselinux1-dev selinux-policy-dev libaudit-dev"
	;;
    hardenedmalloc)
	INSTALL_HARDENED_MALLOC=yes
	# Need clang >= 19 for constexpr.
	PACKAGES="$PACKAGES clang-19"
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
    dropbear-versions)
	INSTALL_DROPBEAR=main
	;;
    putty-*)
	INSTALL_PUTTY=0.83
	PACKAGES="${PACKAGES} cmake"
	;;
    valgrind*)
       PACKAGES="$PACKAGES valgrind"
       ;;
    zlib-*)
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
    brew)
	if [ ! -z "PACKAGES" ]; then
		if brew install $PACKAGES; then
			PACKAGES=""
		fi
	fi
	;;
    setup)
	setup="/cygdrive/$(echo "${CYGWIN_SETUP}" | tr -d : | tr '\' '/')"
	if "${setup}" -q -P `echo "$PACKAGES" | tr ' ' ,`; then
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
     make CC=clang-19 && sudo cp out/libhardened_malloc.so /usr/lib/)
fi

if [ ! -z "${INSTALL_BEARSSL}" ]; then
    (cd ${HOME} &&
     git clone -b "${INSTALL_BEARSSL}" https://bearssl.org/git/BearSSL bearssl &&
     cd bearssl && make -j2 &&
     $SUDO mkdir -p /usr/local/include /usr/local/lib
     $SUDO cp build/libbearssl.a /usr/local/lib &&
     $SUDO cp inc/*.h /usr/local/include)
fi

if [ ! -z "${INSTALL_LIBFIDO2}" ]; then
    (cd ${HOME} &&
     git clone https://github.com/oasislinux/libfido2.git &&
     cd libfido2 && cmake -DCMAKE_INSTALL_PREFIX=/usr . &&
     make -j2 && sudo make install)
fi

if [ ! -z "${INSTALL_AWSLC}" ]; then
    (cd ${HOME} && git clone --depth 1 --branch v1.46.1 https://github.com/aws/aws-lc.git &&
     cd ${HOME}/aws-lc && mkdir build && cd build &&
     cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF .. && ninja &&
     mkdir -p /opt/aws-lc/lib &&
     cp ${HOME}/aws-lc/build/crypto/libcrypto.a /opt/aws-lc/lib &&
     cp -r ${HOME}/aws-lc/include /opt/aws-lc)
fi

if [ ! -z "${INSTALL_ZLIB}" ]; then
    (cd ${HOME} && git clone https://github.com/madler/zlib.git &&
     cd ${HOME}/zlib && ./configure && make &&
     sudo make install prefix=/opt/zlib)
fi

if [ ! -z "${INSTALL_DROPBEAR}" ]; then
	.github/install_dropbear.sh "${INSTALL_DROPBEAR}"
fi
if [ ! -z "${INSTALL_PUTTY}" ]; then
	.github/install_putty.sh "${INSTALL_PUTTY}"
fi

# If we're running on an ephemeral VM, set a random password and set
# up to run the password auth test.
if [ ! -z "${EPHEMERAL_VM}" ]; then

    # This is the github "target" as specified in the yml file.
    # In particular, ubuntu-latest sets the password field to the locked
    # value, so unless we reset it here most of the tests will fail.
    case "${target}" in
    ubuntu-*)
	echo ${target} target: setting random password.
	openssl rand -base64 9 >regress/password
	pw=$(tr -d '\n' <regress/password | openssl passwd -6 -stdin)
	sudo usermod --password "${pw}" runner
	sudo usermod --unlock runner
	;;
    esac
fi
