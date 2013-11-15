#!/usr/bin/ksh

echo "Creating package..."
mkdir -p opt/CertNanny/bin
mkdir -p usr/bin
cp COPYRIGHT opt/CertNanny/COPYRIGHT.sscep
cp sscep_static opt/CertNanny/bin
cp sscep_dyn opt/CertNanny/bin
#arch=$(uname -p)
#ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)
version="$version.0"
sed "s/VERSIONINFO/$version/" < AIX/lpp_template.in > AIX/lpp_template
mkinstallp -d . -T AIX/lpp_template

