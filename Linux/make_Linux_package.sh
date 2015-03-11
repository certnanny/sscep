#!/bin/bash

echo "Creating package..."
#arch=$(uname -p)
#ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)
sed "s/VERSIONINFO/$version/" < Linux/sscep-static.spec.in > Linux/sscep-static.spec
tar --transform "s/^\./sscep-static-$version/" --exclude '.git' -czf $HOME/rpmbuild/SOURCES/sscep-static-$version.tar.gz .
rpmbuild -bb Linux/sscep-static.spec
sed "s/VERSIONINFO/$version/" < Linux/sscep-dyn.spec.in > Linux/sscep-dyn.spec
tar --transform "s/^\./sscep-dyn-$version/" --exclude '.git' -czf $HOME/rpmbuild/SOURCES/sscep-dyn-$version.tar.gz .
rpmbuild -bb Linux/sscep-dyn.spec

