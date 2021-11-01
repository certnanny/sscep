#
# SSCEP spec file for building RPM packages
# usage: rpmbuild -ba scripts/sscep.spec
#

Name:         sscep
Version:      0.10.0
Release:      1
Summary:      Simple SCEP client
License:      BSD
Group:        Productivity/Security
Source:       %{name}-%{version}.tar.gz
URL:          https://github.com/certnanny/sscep
Requires:     openssl >= 1:1.1.0

BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool
BuildRequires: openssl-devel

%description
Simple SCEP (Simple Certificate Enrollment Protocol) client.

%prep
%setup -n %{name}-%{version}

%build
./bootstrap.sh

%configure
make

%install
rm -rf $RPM_BUILD_ROOT

%make_install
install -p mkrequest $RPM_BUILD_ROOT/usr/bin

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/bin/sscep
/usr/bin/mkrequest
%doc /usr/share/doc/sscep/COPYING
%doc /usr/share/doc/sscep/README.md
