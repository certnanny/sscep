#!/bin/bash

echo "Creating package..."
#arch=$(uname -p)
#ts=$(date +'%Y%m%d%H%M%S')
version=$(head -n 1 VERSION)
sed "s/VERSIONINFO/$version/" < Linux/sscep.spec.in > Linux/sscep.spec
tar --transform "s/^\./sscep-$version/" --exclude '.git' -czf $HOME/rpmbuild/SOURCES/sscep-$version.tar.gz .
rpmbuild -bb Linux/sscep.spec

