Summary: AQtion Ethernet driver
Name: Atlantic
Vendor: aQuantia Corporation
Version: %{rawver}
Release: 1
License: GPLv2
Group: System Environment/Kernel
Provides: %{name}
URL:   http://www.aquantia.com/
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildArch: noarch

%description
This package contains aQuantia AQtion Ethernet Linux driver

%prep
rm -rf Linux/.git

%build

%clean
rm -rf %{buildroot}

%post
cd /var/build_aq_drv/%{version}/Linux
make clean
make
make install

%preun
rm -f /lib/modules/$(shell uname -r)/aquantia/atlantic.ko
depmod -a $(shell uname -r)

%install
mkdir -p $RPM_BUILD_ROOT/var/build_aq_drv/%{version}
cp -r Linux $RPM_BUILD_ROOT/var/build_aq_drv/%{version}

%files
%defattr(-,root,root,-)
/var/build_aq_drv/%{version}/Linux
