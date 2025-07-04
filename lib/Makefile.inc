#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################

LIB_VAUTH_CFILES =      \
  vauth/cleartext.c     \
  vauth/cram.c          \
  vauth/digest.c        \
  vauth/digest_sspi.c   \
  vauth/gsasl.c         \
  vauth/krb5_gssapi.c   \
  vauth/krb5_sspi.c     \
  vauth/ntlm.c          \
  vauth/ntlm_sspi.c     \
  vauth/oauth2.c        \
  vauth/spnego_gssapi.c \
  vauth/spnego_sspi.c   \
  vauth/vauth.c

LIB_VAUTH_HFILES =      \
  vauth/digest.h        \
  vauth/ntlm.h          \
  vauth/vauth.h

LIB_VTLS_CFILES =           \
  vtls/bearssl.c            \
  vtls/cipher_suite.c       \
  vtls/gtls.c               \
  vtls/hostcheck.c          \
  vtls/keylog.c             \
  vtls/mbedtls.c            \
  vtls/mbedtls_threadlock.c \
  vtls/openssl.c            \
  vtls/rustls.c             \
  vtls/schannel.c           \
  vtls/schannel_verify.c    \
  vtls/sectransp.c          \
  vtls/vtls.c               \
  vtls/vtls_scache.c        \
  vtls/vtls_spack.c         \
  vtls/wolfssl.c            \
  vtls/x509asn1.c

LIB_VTLS_HFILES =           \
  vtls/bearssl.h            \
  vtls/cipher_suite.h       \
  vtls/gtls.h               \
  vtls/hostcheck.h          \
  vtls/keylog.h             \
  vtls/mbedtls.h            \
  vtls/mbedtls_threadlock.h \
  vtls/openssl.h            \
  vtls/rustls.h             \
  vtls/schannel.h           \
  vtls/schannel_int.h       \
  vtls/sectransp.h          \
  vtls/vtls.h               \
  vtls/vtls_int.h           \
  vtls/vtls_scache.h        \
  vtls/vtls_spack.h         \
  vtls/wolfssl.h            \
  vtls/x509asn1.h

LIB_VQUIC_CFILES = \
  vquic/curl_msh3.c   \
  vquic/curl_ngtcp2.c   \
  vquic/curl_osslq.c   \
  vquic/curl_quiche.c   \
  vquic/vquic.c \
  vquic/vquic-tls.c

LIB_VQUIC_HFILES = \
  vquic/curl_msh3.h   \
  vquic/curl_ngtcp2.h   \
  vquic/curl_osslq.h   \
  vquic/curl_quiche.h   \
  vquic/vquic.h    \
  vquic/vquic_int.h \
  vquic/vquic-tls.h

LIB_VSSH_CFILES =  \
  vssh/libssh.c    \
  vssh/libssh2.c   \
  vssh/curl_path.c \
  vssh/wolfssh.c

LIB_VSSH_HFILES =    \
  vssh/curl_path.h   \
  vssh/ssh.h

LIB_CFILES =         \
  altsvc.c           \
  amigaos.c          \
  asyn-ares.c        \
  asyn-thread.c      \
  base64.c           \
  bufq.c             \
  bufref.c           \
  cf-h1-proxy.c      \
  cf-h2-proxy.c      \
  cf-haproxy.c       \
  cf-https-connect.c \
  cf-socket.c        \
  cfilters.c         \
  conncache.c        \
  connect.c          \
  content_encoding.c \
  cookie.c           \
  curl_addrinfo.c    \
  curl_des.c         \
  curl_endian.c      \
  curl_fnmatch.c     \
  curl_get_line.c    \
  curl_gethostname.c \
  curl_gssapi.c      \
  curl_memrchr.c     \
  curl_multibyte.c   \
  curl_ntlm_core.c   \
  curl_range.c       \
  curl_rtmp.c        \
  curl_sasl.c        \
  curl_sha512_256.c  \
  curl_sspi.c        \
  curl_threads.c     \
  curl_trc.c         \
  cw-out.c           \
  dict.c             \
  dllmain.c          \
  doh.c              \
  dynbuf.c           \
  dynhds.c           \
  easy.c             \
  easygetopt.c       \
  easyoptions.c      \
  escape.c           \
  file.c             \
  fileinfo.c         \
  fopen.c            \
  formdata.c         \
  ftp.c              \
  ftplistparser.c    \
  getenv.c           \
  getinfo.c          \
  gopher.c           \
  hash.c             \
  headers.c          \
  hmac.c             \
  hostasyn.c         \
  hostip.c           \
  hostip4.c          \
  hostip6.c          \
  hostsyn.c          \
  hsts.c             \
  http.c             \
  http1.c            \
  http2.c            \
  http_aws_sigv4.c   \
  http_chunks.c      \
  http_digest.c      \
  http_negotiate.c   \
  http_ntlm.c        \
  http_proxy.c       \
  httpsrr.c          \
  idn.c              \
  if2ip.c            \
  imap.c             \
  inet_ntop.c        \
  inet_pton.c        \
  krb5.c             \
  ldap.c             \
  llist.c            \
  macos.c            \
  md4.c              \
  md5.c              \
  memdebug.c         \
  mime.c             \
  mprintf.c          \
  mqtt.c             \
  multi.c            \
  netrc.c            \
  nonblock.c         \
  noproxy.c          \
  openldap.c         \
  openlock.c         \
  parsedate.c        \
  pingpong.c         \
  pop3.c             \
  progress.c         \
  psl.c              \
  rand.c             \
  rename.c           \
  request.c          \
  rtsp.c             \
  select.c           \
  sendf.c            \
  setopt.c           \
  sha256.c           \
  share.c            \
  slist.c            \
  smb.c              \
  smtp.c             \
  socketpair.c       \
  socks.c            \
  socks_gssapi.c     \
  socks_sspi.c       \
  speedcheck.c       \
  splay.c            \
  strcase.c          \
  strdup.c           \
  strequal.c         \
  strerror.c         \
  strparse.c         \
  strtoofft.c        \
  system_win32.c     \
  telnet.c           \
  tftp.c             \
  timediff.c         \
  timeval.c          \
  transfer.c         \
  url.c              \
  urlapi.c           \
  version.c          \
  version_win32.c    \
  warnless.c         \
  ws.c

LIB_HFILES =         \
  altsvc.h           \
  amigaos.h          \
  arpa_telnet.h      \
  asyn.h             \
  bufq.h             \
  bufref.h           \
  cf-h1-proxy.h      \
  cf-h2-proxy.h      \
  cf-haproxy.h       \
  cf-https-connect.h \
  cf-socket.h        \
  cfilters.h         \
  conncache.h        \
  connect.h          \
  content_encoding.h \
  cookie.h           \
  curl_addrinfo.h    \
  curl_base64.h      \
  curl_ctype.h       \
  curl_des.h         \
  curl_endian.h      \
  curl_fnmatch.h     \
  curl_get_line.h    \
  curl_gethostname.h \
  curl_gssapi.h      \
  curl_hmac.h        \
  curl_krb5.h        \
  curl_ldap.h        \
  curl_md4.h         \
  curl_md5.h         \
  curl_memory.h      \
  curl_memrchr.h     \
  curl_multibyte.h   \
  curl_ntlm_core.h   \
  curl_printf.h      \
  curl_range.h       \
  curl_rtmp.h        \
  curl_sasl.h        \
  curl_setup.h       \
  curl_setup_once.h  \
  curl_sha256.h      \
  curl_sha512_256.h  \
  curl_sspi.h        \
  curl_threads.h     \
  curl_trc.h         \
  curlx.h            \
  cw-out.h           \
  dict.h             \
  doh.h              \
  dynbuf.h           \
  dynhds.h           \
  easy_lock.h        \
  easyif.h           \
  easyoptions.h      \
  escape.h           \
  file.h             \
  fileinfo.h         \
  fopen.h            \
  formdata.h         \
  ftp.h              \
  ftplistparser.h    \
  functypes.h        \
  getinfo.h          \
  gopher.h           \
  hash.h             \
  headers.h          \
  hostip.h           \
  hsts.h             \
  http.h             \
  http1.h            \
  http2.h            \
  http_aws_sigv4.h   \
  http_chunks.h      \
  http_digest.h      \
  http_negotiate.h   \
  http_ntlm.h        \
  http_proxy.h       \
  httpsrr.h          \
  idn.h              \
  if2ip.h            \
  imap.h             \
  inet_ntop.h        \
  inet_pton.h        \
  llist.h            \
  macos.h            \
  memdebug.h         \
  mime.h             \
  mqtt.h             \
  multihandle.h      \
  multiif.h          \
  netrc.h            \
  nonblock.h         \
  openlock.h         \
  noproxy.h          \
  parsedate.h        \
  pingpong.h         \
  pop3.h             \
  progress.h         \
  psl.h              \
  rand.h             \
  rename.h           \
  request.h          \
  rtsp.h             \
  select.h           \
  sendf.h            \
  setopt.h           \
  setup-os400.h      \
  setup-vms.h        \
  setup-win32.h      \
  share.h            \
  sigpipe.h          \
  slist.h            \
  smb.h              \
  smtp.h             \
  sockaddr.h         \
  socketpair.h       \
  socks.h            \
  speedcheck.h       \
  splay.h            \
  strcase.h          \
  strdup.h           \
  strerror.h         \
  strparse.h         \
  strtoofft.h        \
  system_win32.h     \
  telnet.h           \
  tftp.h             \
  timediff.h         \
  timeval.h          \
  transfer.h         \
  url.h              \
  urlapi-int.h       \
  urldata.h          \
  version_win32.h    \
  warnless.h         \
  ws.h

LIB_RCFILES = libcurl.rc

CSOURCES = $(LIB_CFILES) $(LIB_VAUTH_CFILES) $(LIB_VTLS_CFILES) \
  $(LIB_VQUIC_CFILES) $(LIB_VSSH_CFILES)
HHEADERS = $(LIB_HFILES) $(LIB_VAUTH_HFILES) $(LIB_VTLS_HFILES) \
  $(LIB_VQUIC_HFILES) $(LIB_VSSH_HFILES)
