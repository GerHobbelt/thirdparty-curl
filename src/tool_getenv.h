#ifndef HEADER_CURL_TOOL_GETENV_H
#define HEADER_CURL_TOOL_GETENV_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(WIN32) && defined(_UNICODE)
/* returns environment variable value in Unicode UTF-8 encoding. */
char *tool_getenv_utf8(const char *variable);
#endif

/* returns environment variable value in current locale encoding. */
char *tool_getenv_local(const char *variable);

#if defined(WIN32) && defined(_UNICODE)
/* Windows Unicode builds of curl/libcurl always expect UTF-8 strings for
   internal file paths, regardless of current locale. For paths (or other
   values) passed to a dependency that will always expect local encoding, call
   tool_getenv_local directly instead.*/
#define tool_getenv(variable) tool_getenv_utf8(variable)
#else
#define tool_getenv(variable) tool_getenv_local(variable)
#endif

#endif /* HEADER_CURL_TOOL_GETENV_H */
