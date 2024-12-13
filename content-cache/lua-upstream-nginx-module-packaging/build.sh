#!/bin/bash

# sudo apt install libnginx-mod-http-ndk-dev nginx-dev liblua5.4-dev dh-lua

repo=lua-upstream-nginx-module
workdir=/tmp/
rm -Rf $workdir/$repo

git clone https://github.com/openresty/$repo $workdir/$repo

cp -R debian $workdir/$repo/

cd $workdir/$repo
git checkout 7924b2abbcc3269423611e6d7aa66be28f4076f0

dpkg-buildpackage -us -uc
