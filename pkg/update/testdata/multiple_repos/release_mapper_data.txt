| package name            | identifier                     | release service | strip prefix | notes                                                                     |
| ----------------------- | ------------------------------ | --------------- | ------------ | ------------------------------------------------------------------------- |
|acl                      |16                              |RELEASE_MONITOR  |              |                                                                           |
|alsa-lib                 |38                              |RELEASE_MONITOR  |              |                                                                           |
|apk-tools                |20466                           |RELEASE_MONITOR  |              |                                                                           |
|attr                     |137                             |RELEASE_MONITOR  |              |                                                                           |
|autoconf                 |141                             |RELEASE_MONITOR  |              |                                                                           |
|automake                 |144                             |RELEASE_MONITOR  |              |                                                                           |
|bash                     |166                             |RELEASE_MONITOR  |              |                                                                           |
|bazel-5                  |15227                           |RELEASE_MONITOR  |              |SKIP bazel - 5 version stream                                              |
|binutils                 |7981                            |RELEASE_MONITOR  |              |                                                                           |
|bison                    |193                             |RELEASE_MONITOR  |              |                                                                           |
|brotli                   |15235                           |RELEASE_MONITOR  |              |                                                                           |
|bubblewrap               |10937                           |RELEASE_MONITOR  |              |                                                                           |
|busybox                  |230                             |RELEASE_MONITOR  |              |                                                                           |
|bzip2                    |237                             |RELEASE_MONITOR  |              |                                                                           |
|c-ares                   |5840                            |RELEASE_MONITOR  |              |                                                                           |
|ca-certificates          |9026                            |RELEASE_MONITOR  |              |                                                                           |
|check                    |7593                            |RELEASE_MONITOR  |              |                                                                           |
|clang-15                 |11811                           |RELEASE_MONITOR  |              |SKIP clang - 15 version stream                                             |
|cmake                    |306                             |RELEASE_MONITOR  |              |SKIP - includes subset of the version in the melange fetch URL             |
|coreutils                |343                             |RELEASE_MONITOR  |              |                                                                           |
|cosign                   |sigstore/cosign                 |GITHUB           |v             |                                                                           |
|crane                    |google/go-containerregistry     |GITHUB           |              |SKIP UNKNOWN                                                               |
|cups                     |380                             |RELEASE_MONITOR  |              |                                                                           |
|curl                     |381                             |RELEASE_MONITOR  |              |                                                                           |
|dbus                     |5356                            |RELEASE_MONITOR  |              |                                                                           |
|diffutils                |436                             |RELEASE_MONITOR  |              |                                                                           |
|dumb-init                |11582                           |RELEASE_MONITOR  |              |                                                                           |
|encodings                |15051                           |RELEASE_MONITOR  |              |                                                                           |
|envoy                    |envoyproxy/envoy                |GITHUB           |              |SKIP UNKNOWN                                                               |
|execline                 |5482                            |RELEASE_MONITOR  |              |                                                                           |
|expat                    |770                             |RELEASE_MONITOR  |              |                                                                           |
|file                     |807                             |RELEASE_MONITOR  |              |                                                                           |
|findutils                |812                             |RELEASE_MONITOR  |              |                                                                           |
|flex                     |819                             |RELEASE_MONITOR  |              |                                                                           |
|font-util                |15055                           |RELEASE_MONITOR  |              |name=xorg-font-util                                                        |
|fontconfig               |827                             |RELEASE_MONITOR  |              |                                                                           |
|freetype                 |854                             |RELEASE_MONITOR  |              |                                                                           |
|gawk                     |868                             |RELEASE_MONITOR  |              |                                                                           |
|gcc                      |6502                            |RELEASE_MONITOR  |              |                                                                           |
|gdbm                     |882                             |RELEASE_MONITOR  |              |                                                                           |
|giflib                   |1158                            |RELEASE_MONITOR  |              |                                                                           |
|git                      |5350                            |RELEASE_MONITOR  |              |includes release candidates e.g. 2.39.0-rc0                                |
|git-lfs                  |11551                           |RELEASE_MONITOR  |              |                                                                           |
|glibc                    |5401                            |RELEASE_MONITOR  |              |includes Pre-release 9000 https://release-monitoring.org/project/5401/     |
|gmp                      |1186                            |RELEASE_MONITOR  |              |                                                                           |
|go                       |1227                            |RELEASE_MONITOR  |              |                                                                           |
|go-bindata               |                                |                 |              |SKIP UNKNOWN                                                               |
|gperf                    |1237                            |RELEASE_MONITOR  |              |                                                                           |
|grep                     |1251                            |RELEASE_MONITOR  |              |                                                                           |
|grype                    |anchore/grype                   |GITHUB           |              |SKIP UNKNOWN                                                               |
|gzip                     |1290                            |RELEASE_MONITOR  |              |                                                                           |
|help2man                 |1309                            |RELEASE_MONITOR  |              |                                                                           |
|http-parser              |10989                           |RELEASE_MONITOR  |              |                                                                           |
|icu                      |16134                           |RELEASE_MONITOR  |              |SKIP uses unusual version format                                           |
|isl                      |13286                           |RELEASE_MONITOR  |              |SKIP                                                                       |
|jenkins                  |jenkinsci/jenkins               |GITHUB           |              |                                                                           |
|jq                       |13252                           |RELEASE_MONITOR  |              |                                                                           |
|kubectl                  |kubernetes/kubernetes           |GITHUB           |              |SKIP UNKNOWN                                                               |
|lcms                     |1542                            |RELEASE_MONITOR  |              |                                                                           |
|libarchive               |1558                            |RELEASE_MONITOR  |              |                                                                           |
|libbsd                   |1567                            |RELEASE_MONITOR  |              |                                                                           |
|libcap                   |                                |                 |              |SKIP double check as we have a very old version if they are the same package https://release-monitoring.org/project/1569/||
|libedit                  |1599                            |RELEASE_MONITOR  |              |SKIP check as they include the date in the version but we have it hard coded in melange config|
|libev                    |1605                            |RELEASE_MONITOR  |              |                                                                           |
|libevent                 |1606                            |RELEASE_MONITOR  |              |                                                                           |
|libffi                   |1611                            |RELEASE_MONITOR  |              |                                                                           |
|libfontenc               |1613                            |RELEASE_MONITOR  |              |                                                                           |
|libgcrypt                |1623                            |RELEASE_MONITOR  |              |                                                                           |
|libgit2                  |1627                            |RELEASE_MONITOR  |              |                                                                           |
|libgpg-error             |1628                            |RELEASE_MONITOR  |              |                                                                           |
|libice                   |1638                            |RELEASE_MONITOR  |              |                                                                           |
|libjpeg                  |1648                            |RELEASE_MONITOR  |              |                                                                           |
|libmd                    |15525                           |RELEASE_MONITOR  |              |                                                                           |
|libpaper                 |15136                           |RELEASE_MONITOR  |              |                                                                           |
|libpng                   |1705                            |RELEASE_MONITOR  |              |                                                                           |
|libpthread-stubs         |13519                           |RELEASE_MONITOR  |              |                                                                           |
|libretls                 |148759                          |RELEASE_MONITOR  |              |                                                                           |
|libsm                    |1726                            |RELEASE_MONITOR  |              |                                                                           |
|libssh2                  |1730                            |RELEASE_MONITOR  |              |                                                                           |
|libtool                  |1741                            |RELEASE_MONITOR  |              |                                                                           |
|libusb                   |1749                            |RELEASE_MONITOR  |              |                                                                           |
|libuv                    |10784                           |RELEASE_MONITOR  |              |                                                                           |
|libx11                   |1764                            |RELEASE_MONITOR  |              |                                                                           |
|libxau                   |1765                            |RELEASE_MONITOR  |              |                                                                           |
|libxcb                   |1767                            |RELEASE_MONITOR  |              |                                                                           |
|libxdmcp                 |1772                            |RELEASE_MONITOR  |              |                                                                           |
|libxext                  |1774                            |RELEASE_MONITOR  |              |                                                                           |
|libxfixes                |1775                            |RELEASE_MONITOR  |              |                                                                           |
|libxi                    |1778                            |RELEASE_MONITOR  |              |                                                                           |
|libxml2                  |1783                            |RELEASE_MONITOR  |              |                                                                           |
|libxrandr                |1788                            |RELEASE_MONITOR  |              |                                                                           |
|libxrender               |1789                            |RELEASE_MONITOR  |              |                                                                           |
|libxslt                  |13301                           |RELEASE_MONITOR  |              |                                                                           |
|libxt                    |1793                            |RELEASE_MONITOR  |              |                                                                           |
|libxtst                  |1794                            |RELEASE_MONITOR  |              |                                                                           |
|linenoise                |5691                            |RELEASE_MONITOR  |              |                                                                           |
|linux-headers            |6501                            |RELEASE_MONITOR  |              |SKIP - As we want to be conservative providing new APIs                    |
|llvm-libunwind           |1830                            |RELEASE_MONITOR  |              |the mono LLVM repo                                                         |
|llvm-lld                 |1830                            |RELEASE_MONITOR  |              |the mono LLVM repo                                                         |
|llvm15                   |1830                            |RELEASE_MONITOR  |              |SKIP CI failure /home/build/MinGW/Options.td:1:9: error: Could not find include file 'llvm/Option/OptParser.td'. the mono LLVM repo||
|lua5.3                   |                                |                 |              |SKIP check this https://release-monitoring.org/projects/search/?pattern=lua5|
|lua5.3-lzlib             |21513                           |RELEASE_MONITOR  |              |                                                                           |
|lz4                      |1865                            |RELEASE_MONITOR  |              |                                                                           |
|m4                       |1871                            |RELEASE_MONITOR  |              |                                                                           |
|make                     |1877                            |RELEASE_MONITOR  |              |                                                                           |
|maven                    |1894                            |RELEASE_MONITOR  |              |                                                                           |
|meson                    |6472                            |RELEASE_MONITOR  |              |                                                                           |
|mkfontscale              |15043                           |RELEASE_MONITOR  |              |                                                                           |
|mpc                      |1667                            |RELEASE_MONITOR  |              |                                                                           |
|mpdecimal                |11578                           |RELEASE_MONITOR  |              |                                                                           |
|mpfr                     |2019                            |RELEASE_MONITOR  |              |                                                                           |
|ncurses                  |2057                            |RELEASE_MONITOR  |              |SKIP check melange config as fetch URL includes the date https://release-monitoring.org/project/2057/|
|nghttp2                  |8651                            |RELEASE_MONITOR  |              |                                                                           |
|nodejs                   |                                |                 |              |SKIP double check do we want to track latest or LTS? https://release-monitoring.org/projects/search/?pattern=nodejs||
|oniguruma                |11184                           |RELEASE_MONITOR  |              |                                                                           |
|openjdk-11               |                                |                 |              |SKIP check this - we might want to monitor patch versions which release monitor seems to not https://release-monitoring.org/projects/search/?pattern=openjdk||
|openjdk-17               |                                |                 |              |SKIP check this - we might want to monitor patch versions which release monitor seems to not https://release-monitoring.org/projects/search/?pattern=openjdk||
|openssh                  |2565                            |RELEASE_MONITOR  |              |                                                                           |
|openssl                  |2566                            |RELEASE_MONITOR  |              |                                                                           |
|patch                    |2597                            |RELEASE_MONITOR  |              |                                                                           |
|pax-utils                |2601                            |RELEASE_MONITOR  |              |SKIP - latest version has changed URL                                      |
|pcre2                    |5832                            |RELEASE_MONITOR  |              |                                                                           |
|perl                     |13599                           |RELEASE_MONITOR  |              |                                                                           |
|perl-test-pod            |3410                            |RELEASE_MONITOR  |              |                                                                           |
|perl-yaml-syck           |11926                           |RELEASE_MONITOR  |              |                                                                           |
|pkgconf                  |12753                           |RELEASE_MONITOR  |              |                                                                           |
|popt                     |3689                            |RELEASE_MONITOR  |              |                                                                           |
|postgresql-11            |5601                            |RELEASE_MONITOR  |              |SKIP check version stream https://release-monitoring.org/project/5601/     |
|postgresql-12            |5601                            |RELEASE_MONITOR  |              |SKIP check version stream https://release-monitoring.org/project/5601/     |
|postgresql-13            |5601                            |RELEASE_MONITOR  |              |SKIP check version stream https://release-monitoring.org/project/5601/     |
|postgresql-14            |5601                            |RELEASE_MONITOR  |              |SKIP check version stream https://release-monitoring.org/project/5601/     |
|postgresql-15            |5601                            |RELEASE_MONITOR  |              |SKIP check version stream https://release-monitoring.org/project/5601/     |
|procps                   |3708                            |RELEASE_MONITOR  |              |                                                                           |
|py3-appdirs              |6278                            |RELEASE_MONITOR  |              |                                                                           |
|py3-contextlib2          |6215                            |RELEASE_MONITOR  |              |                                                                           |
|py3-flit-core            |44841                           |RELEASE_MONITOR  |              |                                                                           |
|py3-gpep517              |255912                          |RELEASE_MONITOR  |              |                                                                           |
|py3-installer            |197662                          |RELEASE_MONITOR  |              |                                                                           |
|py3-jinja2               |3894                            |RELEASE_MONITOR  |              |                                                                           |
|py3-markupsafe           |3918                            |RELEASE_MONITOR  |              |                                                                           |
|py3-more-itertools       |12201                           |RELEASE_MONITOR  |              |                                                                           |
|py3-ordered-set          |7433                            |RELEASE_MONITOR  |              |SKIP - CI failure cp: can't stat 'ordered_set.egg-info': No such file or directory|
|py3-packaging            |11718                           |RELEASE_MONITOR  |              |                                                                           |
|py3-parsing              |3756                            |RELEASE_MONITOR  |              |                                                                           |
|py3-pep517               |47623                           |RELEASE_MONITOR  |              |                                                                           |
|py3-pip                  |6529                            |RELEASE_MONITOR  |              |                                                                           |
|py3-retrying             |13217                           |RELEASE_MONITOR  |              |                                                                           |
|py3-setuptools           |4021                            |RELEASE_MONITOR  |              |SKIP # NOTE: Be very careful when upgrading this package as upstream aggressively deprecates functionality used by packages in production||
|py3-setuptools-stage0    |                                |                 |              |SKIP stage 0?                                                              |
|py3-six                  |4027                            |RELEASE_MONITOR  |              |                                                                           |
|py3-tomli                |207408                          |RELEASE_MONITOR  |              |                                                                           |
|python3                  |13254                           |RELEASE_MONITOR  |              |SKIP python minor version [is used in the subpackage](https://github.com/wolfi-dev/os/blob/fbdc30376679526ce0c5bec80debeb111512ea7e/python3.yaml#LL90C61-L90C65) so upgr|              ade to 3.11 fails|
|readline                 |4173                            |RELEASE_MONITOR  |              |                                                                           |
|regclient                |                                |                 |              |SKIP UNKNOWN                                                               |
|rhash                    |13843                           |RELEASE_MONITOR  |              |                                                                           |
|rsync                    |4217                            |RELEASE_MONITOR  |              |                                                                           |
|ruby-3.0                 |4223                            |RELEASE_MONITOR  |              |SKIP version stream                                                        |
|ruby-3.1                 |4223                            |RELEASE_MONITOR  |              |SKIP version stream                                                        |
|rust-stage0              |                                |                 |              |SKIP stage 0                                                               |
|s6                       |5485                            |RELEASE_MONITOR  |              |                                                                           |
|samurai                  |96779                           |RELEASE_MONITOR  |              |                                                                           |
|scdoc                    |68662                           |RELEASE_MONITOR  |              |                                                                           |
|sed                      |4789                            |RELEASE_MONITOR  |              |                                                                           |
|skalibs                  |5486                            |RELEASE_MONITOR  |              |                                                                           |
|skopeo                   |9216                            |RELEASE_MONITOR  |              |                                                                           |
|sqlite                   |4877                            |RELEASE_MONITOR  |              |                                                                           |
|su-exec                  |                                |                 |              |SKIP UNKNOWN                                                               |
|texinfo                  |4958                            |RELEASE_MONITOR  |              |                                                                           |
|tini                     |13826                           |RELEASE_MONITOR  |              |                                                                           |
|tree                     |5006                            |RELEASE_MONITOR  |              |                                                                           |
|trivy                    |141362                          |RELEASE_MONITOR  |              |                                                                           |
|ttf-dejavu               |418                             |RELEASE_MONITOR  |              |SKIP check format of version                                               |
|tzdata                   |5021                            |RELEASE_MONITOR  |              |                                                                           |
|util-macros              |5252                            |RELEASE_MONITOR  |              |                                                                           |
|wasi-libc                |                                |                 |              |SKIP UNKNOWN                                                               |
|wget                     |5124                            |RELEASE_MONITOR  |              |                                                                           |
|xcb-proto                |13646                           |RELEASE_MONITOR  |              |                                                                           |
|xmlto                    |13307                           |RELEASE_MONITOR  |              |                                                                           |
|xorgproto                |17190                           |RELEASE_MONITOR  |              |                                                                           |
|xtrans                   |13440                           |RELEASE_MONITOR  |              |                                                                           |
|xz                       |5277                            |RELEASE_MONITOR  |              |                                                                           |
|zip                      |10080                           |RELEASE_MONITOR  |              |                                                                           |
|zlib                     |5303                            |RELEASE_MONITOR  |              |                                                                           |
|zstd                     |12083                           |RELEASE_MONITOR  |              |                                                                           |