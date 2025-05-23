#ifndef HEADER_CURL_TOOL_DOSWIN_H
#define HEADER_CURL_TOOL_DOSWIN_H
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
#include "tool_setup.h"

#if defined(_WIN32) || defined(MSDOS)


#ifdef __DJGPP__
char **__crt0_glob_function(char *arg);
#endif

#ifdef _WIN32

#if !defined(CURL_WINDOWS_UWP) && \
  !defined(CURL_DISABLE_CA_SEARCH) && !defined(CURL_CA_SEARCH_SAFE)
CURLcode FindWin32CACert(struct OperationConfig *config,
                         const TCHAR *bundle_file);
#endif
struct curl_slist *GetLoadedModulePaths(void);
CURLcode win32_init(void);

#endif /* _WIN32 */

#endif /* _WIN32 || MSDOS */

#endif /* HEADER_CURL_TOOL_DOSWIN_H */
