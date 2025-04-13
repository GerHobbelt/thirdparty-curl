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

#ifdef HAVE_IO_H
#  include <io.h>
#endif

#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif

#include "tool_binmode.h"

#include "memdebug.h" /* keep this as LAST include */

void Curl_set_binmode(FILE *stream)
{
#if defined(HAVE_SETMODE) || defined(HAVE__SETMODE)
#ifdef O_BINARY
#  ifdef __HIGHC__
  _setmode(stream, O_BINARY);
#  elif defined(HAVE__SETMODE)
  (void)_setmode(fileno(stream), O_BINARY);
#  else
  (void)setmode(fileno(stream), O_BINARY);
#  endif
#endif
#endif /* HAVE_SETMODE || HAVE__SETMODE */

  Curl_reset_vbuf_to_default(stream);
}


void Curl_reset_vbuf_to_default(FILE *stream)
{
#if ( defined(HAVE_SETVBUF) || defined(_MSC_VER) ) && defined(_IONBF) && ( defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64) )
  (void)setvbuf(stream, NULL, _IONBF, 0);
#else
  (void)stream;
#endif
}

