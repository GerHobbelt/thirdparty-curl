/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curlcheck.h"

#include "vtls/hostcheck.h" /* from the lib dir */

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{
  /* done before shutting down and exiting */
}

/* only these backends define the tested functions */
#if defined(USE_OPENSSL) || defined(USE_SCHANNEL)
#include "vtls/hostcheck.h"
struct testcase {
  const char *host;
  const char *pattern;
  bool match;
};

static struct testcase tests[] = {
  {"", "", FALSE},
  {"a", "", FALSE},
  {"", "b", FALSE},
  {"a", "b", FALSE},
  {"aa", "bb", FALSE},
  {"\xff", "\xff", TRUE},
  {"aa.aa.aa", "aa.aa.bb", FALSE},
  {"aa.aa.aa", "aa.aa.aa", TRUE},
  {"aa.aa.aa", "*.aa.bb", FALSE},
  {"aa.aa.aa", "*.aa.aa", TRUE},
  {"192.168.0.1", "192.168.0.1", TRUE},
  {"192.168.0.1", "*.168.0.1", FALSE},
  {"192.168.0.1", "*.0.1", FALSE},
  {"h.ello", "*.ello", FALSE},
  {"h.ello.", "*.ello", FALSE},
  {"h.ello", "*.ello.", FALSE},
  {"h.e.llo", "*.e.llo", TRUE},
  {"h.e.llo", " *.e.llo", FALSE},
  {" h.e.llo", "*.e.llo", TRUE},
  {"h.e.llo.", "*.e.llo", TRUE},
  {"*.e.llo.", "*.e.llo", TRUE},
  {"************.e.llo.", "*.e.llo", TRUE},
  {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
   "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
   "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
   "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
   ".e.llo.", "*.e.llo", TRUE},
  {"\xfe\xfe.e.llo.", "*.e.llo", TRUE},
  {"h.e.llo.", "*.e.llo.", TRUE},
  {"h.e.llo", "*.e.llo.", TRUE},
  {".h.e.llo", "*.e.llo.", FALSE},
  {"h.e.llo", "*.*.llo.", FALSE},
  {"h.e.llo", "h.*.llo", FALSE},
  {"h.e.llo", "h.e.*", FALSE},
  {"hello", "*.ello", FALSE},
  {"hello", "**llo", FALSE},
  {"bar.foo.example.com", "*.example.com", FALSE},
  {"foo.example.com", "*.example.com", TRUE},
  {"baz.example.net", "b*z.example.net", FALSE},
  {"foobaz.example.net", "*baz.example.net", FALSE},
  {"xn--l8j.example.local", "x*.example.local", FALSE},
  {"xn--l8j.example.net", "*.example.net", TRUE},
  {"xn--l8j.example.net", "*j.example.net", FALSE},
  {"xn--l8j.example.net", "xn--l8j.example.net", TRUE},
  {"xn--l8j.example.net", "xn--l8j.*.net", FALSE},
  {"xl8j.example.net", "*.example.net", TRUE},
  {"fe80::3285:a9ff:fe46:b619", "*::3285:a9ff:fe46:b619", FALSE},
  {"fe80::3285:a9ff:fe46:b619", "fe80::3285:a9ff:fe46:b619", TRUE},
  {NULL, NULL, FALSE}
};

UNITTEST_START

/* only these backends define the tested functions */
#if defined(USE_OPENSSL) || defined(USE_GSKIT)

  /* here you start doing things and checking that the results are good */

fail_unless(Curl_cert_hostcheck(STRCONST("www.example.com"),
                                STRCONST("www.example.com")), "good 1");
fail_unless(Curl_cert_hostcheck(STRCONST("*.example.com"),
                                STRCONST("www.example.com")),
            "good 2");
fail_unless(Curl_cert_hostcheck(STRCONST("xxx*.example.com"),
                                STRCONST("xxxwww.example.com")), "good 3");
fail_unless(Curl_cert_hostcheck(STRCONST("f*.example.com"),
                                STRCONST("foo.example.com")), "good 4");
fail_unless(Curl_cert_hostcheck(STRCONST("192.168.0.0"),
                                STRCONST("192.168.0.0")), "good 5");

fail_if(Curl_cert_hostcheck(STRCONST("xxx.example.com"),
                            STRCONST("www.example.com")), "bad 1");
fail_if(Curl_cert_hostcheck(STRCONST("*"),
                            STRCONST("www.example.com")),"bad 2");
fail_if(Curl_cert_hostcheck(STRCONST("*.*.com"),
                            STRCONST("www.example.com")), "bad 3");
fail_if(Curl_cert_hostcheck(STRCONST("*.example.com"),
                            STRCONST("baa.foo.example.com")), "bad 4");
fail_if(Curl_cert_hostcheck(STRCONST("f*.example.com"),
                            STRCONST("baa.example.com")), "bad 5");
fail_if(Curl_cert_hostcheck(STRCONST("*.com"),
                            STRCONST("example.com")), "bad 6");
fail_if(Curl_cert_hostcheck(STRCONST("*fail.com"),
                            STRCONST("example.com")), "bad 7");
fail_if(Curl_cert_hostcheck(STRCONST("*.example."),
                            STRCONST("www.example.")), "bad 8");
fail_if(Curl_cert_hostcheck(STRCONST("*.example."),
                            STRCONST("www.example")), "bad 9");
fail_if(Curl_cert_hostcheck(STRCONST(""), STRCONST("www")), "bad 10");
fail_if(Curl_cert_hostcheck(STRCONST("*"), STRCONST("www")), "bad 11");
fail_if(Curl_cert_hostcheck(STRCONST("*.168.0.0"),
                            STRCONST("192.168.0.0")), "bad 12");
fail_if(Curl_cert_hostcheck(STRCONST("www.example.com"),
                            STRCONST("192.168.0.0")), "bad 13");

#ifdef ENABLE_IPV6
fail_if(Curl_cert_hostcheck(STRCONST("*::3285:a9ff:fe46:b619"),
                            STRCONST("fe80::3285:a9ff:fe46:b619")), "bad 14");
fail_unless(Curl_cert_hostcheck(STRCONST("fe80::3285:a9ff:fe46:b619"),
                                STRCONST("fe80::3285:a9ff:fe46:b619")),
            "good 6");
#endif

{
  int i;
  for(i = 0; tests[i].host; i++) {
    if(tests[i].match != Curl_cert_hostcheck(tests[i].pattern,
                                             strlen(tests[i].pattern),
                                             tests[i].host,
                                             strlen(tests[i].host))) {
      fprintf(stderr,
              "HOST: %s\n"
              "PTRN: %s\n"
              "did %sMATCH\n",
              tests[i].host,
              tests[i].pattern,
              tests[i].match ? "NOT ": "");
      unitfail++;
    }
  }
}

#endif

  /* you end the test code like this: */

UNITTEST_STOP

#endif	// OPENSSL || USE_SCHANNEL

