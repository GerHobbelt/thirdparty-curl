/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "tool_setup.h"

#include "tool_getenv.h"

#include "curlx.h"
#include "memdebug.h" /* keep this as LAST include */

#if defined(WIN32) && defined(_UNICODE)
char *curl_getenv_utf8(const char *variable)
{
  char *buf;
  WCHAR *w_buf, *w_var;
  DWORD count, rc;

  w_var = curlx_convert_UTF8_to_wchar(variable);
  if(!w_var)
    return NULL;

  count = GetEnvironmentVariableW(w_var, NULL, 0);
  if(!count || count > 32768) {
    free(w_var);
    return NULL;
  }

  w_buf = malloc(count * sizeof(WCHAR));
  if(!w_buf) {
    free(w_var);
    return NULL;
  }

  rc = GetEnvironmentVariableW(w_var, w_buf, count);
  if(!rc || rc >= count) {
    free(w_var);
    free(w_buf);
    return NULL;
  }

  buf = curlx_convert_wchar_to_UTF8(w_buf);
  free(w_var);
  free(w_buf);
  return buf;
}
#endif /* WIN32 && _UNICODE */

char *curl_getenv_local(const char *variable)
{
  char *dupe, *env;
  /* !checksrc! disable BANNEDFUNC 1 */
  env = curl_getenv(variable);
  if(!env)
    return NULL;

  dupe = strdup(env);
  curl_free(env);
  return dupe;
}
