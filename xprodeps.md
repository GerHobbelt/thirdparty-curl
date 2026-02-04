# curl dependencies
|project|license [^_l]|description [dependencies]|version|source|diff [^_d]|
|-------|-------------|--------------------------|-------|------|----------|
|<a id='curl' />[curl](http://curl.haxx.se/libcurl/)|[curl](http://curl.haxx.se/docs/copyright.html 'curl license inspired by MIT/X, but not identical')|the multiprotocol file transfer library [deps: _c-ares, libssh2_]| |[upstream](https://github.com/curl/curl 'github.com/curl/curl')|  [patch]|
|<a id='c-ares' />[c-ares](http://c-ares.haxx.se/)|[MIT](http://c-ares.haxx.se/license.html 'MIT License')|C library for asynchronous DNS requests (including name resolves)|[v1.18.1.2](https://github.com/externpro/c-ares/releases/tag/v1.18.1.2 'release')|[repo](https://github.com/externpro/c-ares 'github.com/externpro/c-ares') [upstream](https://github.com/c-ares/c-ares 'github.com/c-ares/c-ares')|[diff](https://github.com/externpro/c-ares/compare/cares-1_18_1...v1.18.1.2 'github.com/externpro/c-ares/compare/cares-1_18_1...v1.18.1.2') [patch]|
|<a id='libssh2' />[libssh2](http://www.libssh2.org/)|[BSD-3-Clause](http://www.libssh2.org/license.html 'BSD 3-Clause New or Revised License')|client-side C library implementing SSH2 protocol [deps: _openssl, zlib_]|[v1.9.0.3](https://github.com/externpro/libssh2/releases/tag/v1.9.0.3 'release')|[repo](https://github.com/externpro/libssh2 'github.com/externpro/libssh2') [upstream](https://github.com/libssh2/libssh2 'github.com/libssh2/libssh2')|[diff](https://github.com/externpro/libssh2/compare/libssh2-1.9.0...v1.9.0.3 'github.com/externpro/libssh2/compare/libssh2-1.9.0...v1.9.0.3') [patch]|
|<a id='openssl' />[openssl](http://www.openssl.org/)|[BSD-style](http://www.openssl.org/source/license.html 'dual OpenSSL and SSLeay License: both are BSD-style licenses')|Cryptography and SSL/TLS Toolkit [pvt deps: _nasm, yasm_]|[v1.1.1l.3](https://github.com/externpro/openssl/releases/tag/v1.1.1l.3 'release')|[repo](https://github.com/externpro/openssl 'github.com/externpro/openssl') [upstream](https://github.com/openssl/openssl 'github.com/openssl/openssl')|[diff](https://github.com/externpro/openssl/compare/OpenSSL_1_1_1l...v1.1.1l.3 'github.com/externpro/openssl/compare/OpenSSL_1_1_1l...v1.1.1l.3') [intro]|
|<a id='zlib' />[zlib](https://zlib.net 'zlib website')|[permissive](https://zlib.net/zlib_license.html 'zlib/libpng license, see https://en.wikipedia.org/wiki/Zlib_License')|compression library|[v1.3.1.3](https://github.com/externpro/zlib/releases/tag/v1.3.1.3 'release')|[repo](https://github.com/externpro/zlib 'github.com/externpro/zlib') [upstream](https://github.com/madler/zlib 'github.com/madler/zlib')|[diff](https://github.com/externpro/zlib/compare/v1.3.1...v1.3.1.3 'github.com/externpro/zlib/compare/v1.3.1...v1.3.1.3') [patch]|
|<a id='nasm' />[nasm](https://www.nasm.us/)|[BSD-2-Clause](https://www.nasm.us/ 'BSD 2-Clause Simplified License')|The Netwide Assembler - an 80x86 and x86-64 assembler (MSW-only)|[v2.14.02.3](https://github.com/externpro/nasm/releases/tag/v2.14.02.3 'release')|[repo](https://github.com/externpro/nasm 'github.com/externpro/nasm')|[diff](https://github.com/externpro/nasm/compare/v0...v2.14.02.3 'github.com/externpro/nasm/compare/v0...v2.14.02.3') [bin]|
|<a id='yasm' />[yasm](http://yasm.tortall.net/)|[BSD-2-Clause](https://github.com/yasm/yasm/blob/v1.3.0/COPYING 'BSD 2-Clause Simplified License')|assembler and disassembler for the Intel x86 architecture|[v1.3.0.2](https://github.com/externpro/yasm/releases/tag/v1.3.0.2 'release')|[repo](https://github.com/externpro/yasm 'github.com/externpro/yasm') [upstream](https://github.com/yasm/yasm 'github.com/yasm/yasm')|[diff](https://github.com/externpro/yasm/compare/v1.3.0...v1.3.0.2 'github.com/externpro/yasm/compare/v1.3.0...v1.3.0.2') [patch]|

![deps](xprodeps.svg 'dependencies')

Dependency version check: all 6 parent-manifest versions match pinned versions.

|diff  |description|
|------|-----------|
|patch |diff modifies/patches existing cmake|
|intro |diff introduces cmake|
|auto  |diff adds cmake to replace autotools/configure/make|
|native|diff adds cmake but uses existing build system|
|bin   |diff adds cmake to repackage binaries built elsewhere|
|fetch |diff adds cmake and utilizes FetchContent|

[^_l]: see [SPDX License List](https://spdx.org/licenses/ '') for a list of commonly found licenses
[^_d]: see table above with description of diff
