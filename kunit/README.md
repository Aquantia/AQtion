# KUnit tests

For more information on KUnit and unit tests in general please refer to the [KUnit documentation](https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html)

Direct link to KUnit API reference: [url](https://www.kernel.org/doc/html/latest/dev-tools/kunit/api/index.html)

### How to build and run unit tests

> **NB!** Back up your existig `.config`, because the steps below will overwrite it.

You need to have both kernel sources (referred to as `<linux-src>`from now on)  and driver sources (`<drv-src>`).

Cut-n-paste steps:
```
cd <linux-src>
sudo mount --bind <drv-src> <linux-src>/drivers/net/ethernet/aquantia

mv --backup=numbered .config .config.bak
make mrproper
make ARCH=um mrproper
grep -v -e 'CONFIG_KUNIT_TEST=y' -e 'CONFIG_KUNIT_EXAMPLE_TEST=y' arch/um/configs/kunit_defconfig >.kunitconfig
cat >>.kunitconfig <<EOF
CONFIG_NET=y
CONFIG_ETHERNET=y
CONFIG_MACSEC=y
CONFIG_NET_VENDOR_AQUANTIA=y
CONFIG_AQTION_KUNIT_TESTS=y
EOF
./tools/testing/kunit/kunit.py run --build_dir=.
mv -f .config.bak .config

sudo umount <linux-src>/drivers/net/ethernet/aquantia
```
