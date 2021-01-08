#
# SSCEP spec file for building RPM packages
# usage: rpmbuild -ba scripts/sscep.spec
#

Name:         sscep
Version:      0.8.1
Release:      1
Summary:      Simple SCEP client
License:      BSD
Group:        Productivity/Security
Source:       %{name}-%{version}.tar.gz
URL:          https://github.com/certnanny/sscep
Requires:     openssl >= 1:0.9.7

%description
Simple SCEP (Simple Certificate Enrollment Protocol) client.

%prep
%setup -n %{name}-%{version}

%build
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
%make_install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/bin/sscep
%doc /usr/share/doc/sscep/COPYING
%doc /usr/share/doc/sscep/README.md
