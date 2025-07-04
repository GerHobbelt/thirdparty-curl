#ifndef HEADER_CURL_DYNBUF_H
#define HEADER_CURL_DYNBUF_H
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

#include <curl/curl.h>

struct curl_dynbuf {
  char *bufr;    /* point to a null-terminated allocated buffer */
  size_t leng;   /* number of bytes *EXCLUDING* the null-terminator */
  size_t allc;   /* size of the current allocation */
  size_t toobig; /* size limit for the buffer */
#ifdef DEBUGBUILD
  int init;     /* detect API usage mistakes */
#endif
};

void Curl_dyn_init(struct curl_dynbuf *s, size_t toobig);
void Curl_dyn_free(struct curl_dynbuf *s);
CURLcode Curl_dyn_addn(struct curl_dynbuf *s, const void *mem, size_t len)
  WARN_UNUSED_RESULT;
CURLcode Curl_dyn_add(struct curl_dynbuf *s, const char *str)
  WARN_UNUSED_RESULT;
CURLcode Curl_dyn_addf(struct curl_dynbuf *s, const char *fmt, ...)
  WARN_UNUSED_RESULT CURL_PRINTF(2, 3);
CURLcode Curl_dyn_vaddf(struct curl_dynbuf *s, const char *fmt, va_list ap)
  WARN_UNUSED_RESULT CURL_PRINTF(2, 0);
void Curl_dyn_reset(struct curl_dynbuf *s);
CURLcode Curl_dyn_tail(struct curl_dynbuf *s, size_t trail);
CURLcode Curl_dyn_setlen(struct curl_dynbuf *s, size_t set);
char *Curl_dyn_ptr(const struct curl_dynbuf *s);
unsigned char *Curl_dyn_uptr(const struct curl_dynbuf *s);
size_t Curl_dyn_len(const struct curl_dynbuf *s);

/* returns 0 on success, -1 on error */
/* The implementation of this function exists in mprintf.c */
int Curl_dyn_vprintf(struct curl_dynbuf *dyn, const char *format, va_list ap_save);

/* Take the buffer out of the dynbuf. Caller has ownership and
 * dynbuf resets to initial state. */
char *Curl_dyn_take(struct curl_dynbuf *s, size_t *plen);

/* Dynamic buffer max sizes */
#define DYN_DOH_RESPONSE    3000
#define DYN_DOH_CNAME       256
#define DYN_PAUSE_BUFFER    (64 * 1024 * 1024)
#define DYN_HAXPROXY        2048
#define DYN_HTTP_REQUEST    (1024*1024)
#define DYN_APRINTF         8000000
#define DYN_RTSP_REQ_HEADER (64*1024)
#define DYN_TRAILERS        (64*1024)
#define DYN_PROXY_CONNECT_HEADERS 16384
#define DYN_QLOG_NAME       1024
#define DYN_H1_TRAILER      4096
#define DYN_PINGPPONG_CMD   (64*1024)
#define DYN_IMAP_CMD        (64*1024)
#define DYN_MQTT_RECV       (64*1024)
#endif
