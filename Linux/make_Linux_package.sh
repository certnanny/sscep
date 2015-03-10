#!/bin/bash

echo "Creating package..."
#arch=$(uname -p)
#ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)

sed "s/VERSIONINFO/$version/" < Linux/sscep-static.spec.in > Linux/sscep-static.spec
mkdir sscep-static-$version
cp sscep_static COPYRIGHT README sscep-static-$version/
tar -czf $HOME/rpmbuild/SOURCES/sscep-static-$version.tar.gz sscep-static-$version
rm -rf sscep-static-$version
rpmbuild -bb Linux/sscep-static.spec

sed "s/VERSIONINFO/$version/" < Linux/sscep-dyn.spec.in > Linux/sscep-dyn.spec
mkdir sscep-dyn-$version
cp sscep_dyn COPYRIGHT README sscep-dyn-$version/
tar -czf $HOME/rpmbuild/SOURCES/sscep-dyn-$version.tar.gz sscep-dyn-$version
rm -rf sscep-dyn-$version
rpmbuild -bb Linux/sscep-dyn.spec

