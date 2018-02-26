#!/bin/sh
set -x
version=`git describe --tags --abbrev=4  | sed 's/\(.*\)-.*/\1/' | sed 's/-/./' | sed 's/v//'`

if [ -e $version ]; then
        version=`date +%s`
fi

DRV_ROOT=$PWD
DEB_ROOT=$PWD/../build
DEB_DEBIAN=$DEB_ROOT/DEBIAN
DEB_CONTROL=$DEB_DEBIAN/control
SRC=/var/build_aq_drv/${version}/Linux
DEB_SRC=$DEB_ROOT/$SRC
DEB_OUT=$DRV_ROOT
TARGET=atlantic

rm -rf $DEB_ROOT

mkdir -p $DEB_DEBIAN || exit 1
mkdir -p $DEB_SRC || exit 1

cp -r $DRV_ROOT/* $DEB_SRC

echo "Package: Atlantic
Maintainer: Anatoly Vildemanov <avildem@aquantia.com>
Build-Depends: debhelper (>= 8.0.0)
Version: $version
Section: utils
Architecture: all
Description: This package contains aQuantia AQtion Ethernet Linux driver" > $DEB_CONTROL || exit 1

echo "#!/bin/bash
KERNEL=/lib/modules/\$(uname -r)/aquantia/$TARGET.ko
mv \$KERNEL \$KERNEL.bac || true
depmod -a \$(uname -r)
rmmod $TARGET.ko || true
" > $DEB_DEBIAN/preinst || exit 1

echo "#!/bin/bash
cd $SRC
AQ_KERNEL=/lib/modules/\$(uname -r)/aquantia/
KERNEL=\$AQ_KERNEL/$TARGET.ko
make all
chmod 644 $TARGET.ko
mkdir -p \$AQ_KERNEL
cp $TARGET.ko \$AQ_KERNEL
depmod -a \$(uname -r)
insmod $TARGET.ko
" > $DEB_DEBIAN/postinst || exit 1

echo "#!/bin/bash
rmmod $TARGET.ko || true
KERNEL=/lib/modules/\$(uname -r)/aquantia/$TARGET.ko
rm -rf $KERNEL
depmod -a \$(uname -r)

" > $DEB_DEBIAN/postrm || exit 1

chmod 755 $DEB_DEBIAN/preinst $DEB_DEBIAN/postinst $DEB_DEBIAN/postrm

deb_name='atlantic_'$version'.deb'

fakeroot dpkg-deb --build  $DEB_ROOT $deb_name