The lua-upstream-nginx-module is currently not part of the distribution.

To ease the deployment and maintenance of lua-upstream-nginx-module, we build a deb locally that will be deployed with the charm and deployed on the nginx servers. The main benefit is that we ensure this way that the module is compiled with the same options as nginx.

To do so, we use `dpkg-buildpackage` in charmcraft.yaml in the 'nginx-module-lua-upstream' part.

`dpkg-buildbackage` requires at least the 3 files in the `debian` folder to build the package:
- changelog: changes introduced in each version (not important in our context as we are not publishing this deb)
- control: the build dependencies and runtime dependencies
    - The nginx-dev dependency is the most interesting for us as it provides helpers to build nginx-modules.
- rules: the `makefile` rules to build the package
    - The "with-nginx" is calling the helper provided by nginx-dev and will set all compile options for nginx modules.
    - The "with-lua" is calling `Lua` helpers provided by `dh_lua` (I still had to manually include /usr/include/lua5.1 though).
    - The "-I$(CURDIR)/debian/" includes headers for lua-nginx-module that we dynamically fetch in charmcraft as there are no lua-nginx-module-dev package available.
