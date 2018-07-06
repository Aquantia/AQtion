#!/bin/sh

# error code
ERR_OK=0
ERR_SCRIPT=1
ERR_DRIVER_NOT_ADD=200
ERR_DRIVER_ALREADY_ADD=$(expr ${ERR_DRIVER_NOT_ADD} + 1)

get_version_driver ()
{
	local FILENAME="ver.h"

	local MAJOR=`   awk -n '/NIC_MAJOR_DRIVER_VERSION/    {print $3}' ${FILENAME}`
	local MINOR=`   awk -n '/NIC_MINOR_DRIVER_VERSION/    {print $3}' ${FILENAME}`
	local BUILD=`   awk -n '/NIC_BUILD_DRIVER_VERSION/    {print $3}' ${FILENAME}`
	local REVISION=`awk -n '/NIC_REVISION_DRIVER_VERSION/ {print $3}' ${FILENAME}`

	echo "${MAJOR}.${MINOR}.${BUILD}.${REVISION}"
}

remove_driver ()
{
	case ${@} in
		${ERR_DRIVER_ALREADY_ADD} ) ;;
		${ERR_DRIVER_NOT_ADD}     ) rm -rf ${MODULE_SRC} ;;
		*                         ) dkms remove ${MODULE_NAME}/${MODULE_VERSION} --all || exit ${ERR_SCRIPT}
		                            rm -rf ${MODULE_SRC} ;;
	esac

	exit ${@}
}

install_driver ()
{
	mkdir -p ${MODULE_SRC}
	cp -r * ${MODULE_SRC}

cat <<EOF >/usr/src/${PACKAGE_NAME}/dkms.conf
	PACKAGE_NAME="${MODULE_NAME}"
	BUILT_MODULE_NAME[0]="${MODULE_NAME}"
	PACKAGE_VERSION="${MODULE_VERSION}"
	DEST_MODULE_LOCATION[0]="/kernel/drivers/net/ethernet/aquantia"
	AUTOINSTALL="yes"
EOF

	dkms add ${MODULE_NAME}/${MODULE_VERSION}
	local ERR=${?}
	if [ ${ERR} != 0 ] ; then
		if [ "${ERR}" = "3" ] ; then
			remove_driver ${ERR_DRIVER_ALREADY_ADD} > /dev/null
		else
			remove_driver ${ERR_DRIVER_NOT_ADD}     > /dev/null
		fi
	fi

	dkms build   ${MODULE_NAME}/${MODULE_VERSION} || remove_driver ${?} > /dev/null
	dkms install ${MODULE_NAME}/${MODULE_VERSION} || remove_driver ${?} > /dev/null
}

uninstall_driver ()
{
	remove_driver ${ERR_OK}
}

get_uninstalled_packages ()
{
	local UNINSTALLED=""

	for PACKAGE in ${PACKAGES}
	do
		${CMD} ${PACKAGE} > /dev/null
		if [ "${?}" != "0" ] ; then
			UNINSTALLED="${UNINSTALLED} ${PACKAGE}"
		fi
	done

	echo "${UNINSTALLED}"
}

get_distro_os ()
{
	local OS=`uname`
	if [ "${OS}" = "Linux" ] ; then
		if [ -f /etc/redhat-release ] ; then
			DISTRO_NAME='redhat'
		elif [ -f /etc/debian_version ] ; then
			DISTRO_NAME='debian'
		elif [ -f /etc/SuSE-release ] ; then
			DISTRO_NAME='suse'
		elif [ -f /etc/mandrake-release ] ; then
			DISTRO_NAME='mandrake'
		fi
	else
		DISTRO_NAME="undefined"
	fi

	echo ${DISTRO_NAME}
}

main ()
{
	YUM="yum"
	APT_GET="apt-get"
	DKMS="dkms"
	GAWK="gawk"
	CMD=""
	DISTRO=$(get_distro_os)
	if [ "${DISTRO}" = "debian" ] ; then
		PACKET_MNG="${APT_GET}"
		LINUX_HEADERS="linux-headers-`uname -r`"
		TOOLS="build-essential"
		CMD="dpkg-query -l"
	elif [ "${DISTRO}" = "redhat" ] ; then
		PACKET_MNG="${YUM}"
		LINUX_HEADERS="kernel-devel-`uname -r`"
		TOOLS="gcc gcc-c++ make"
		CMD="${YUM} list installed"
	else
		echo "Sorry, your operating system ${DISTRO} is not supported."
		exit ${ERR_SCRIPT}
	fi

	# necessary packages
	PACKAGES="${LINUX_HEADERS} ${DKMS} ${GAWK} ${TOOLS}"
	UNINSTALLED_PACKAGES=$(get_uninstalled_packages)

	if [ ! -z "${UNINSTALLED_PACKAGES}" ] ; then
		echo "Please install the necessary packages${UNINSTALLED_PACKAGES}."
		echo "Example: sudo ${PACKET_MNG} install${UNINSTALLED_PACKAGES}."
		exit ${ERR_SCRIPT}
	fi

	MODULE_NAME="atlantic"
	MODULE_VERSION=$(get_version_driver)
	PACKAGE_NAME="${MODULE_NAME}-${MODULE_VERSION}"
	MODULE_SRC="/usr/src/${PACKAGE_NAME}"

	case ${1} in
		install   ) install_driver ;;
		uninstall ) uninstall_driver ;;
		*         ) echo "Sorry, invalid parameters, please enter: ${0} install or ${0} uninstall."
		            exit ${ERR_SCRIPT} ;;
	esac
}

main ${1}
