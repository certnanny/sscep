#!/usr/bin/bash

echo "Creating package..."
mkdir -p opt/CertNanny/bin
mkdir -p usr/bin
cp COPYRIGHT opt/CertNanny/COPYRIGHT.sscep
cp sscep_static opt/CertNanny/bin
cp sscep_dyn opt/CertNanny/bin
arch=$(uname -p)
ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)
sed "s/UNAME-P-ARCHITECTURE/$arch/" < Solaris/pkginfo.template | sed "s/DATETIMESTAMP/$ts/" | sed "s/VERSIONINFO/$version/" > Solaris/pkginfo
pkgmk -o -r . -d /tmp -f Solaris/Prototype
thisdir=$(pwd)
cd /tmp
tar cf - CertNanny-sscep | gzip -9 -c > $thisdir/CertNanny-sscep.$arch.$version.pkg.tar.gz
echo "Solaris installation package created: CertNanny-sscep.$arch.$version.pkg.tar.gz"

