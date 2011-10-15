/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * RFC3501 IMAPv4 protocol
 * RFC5092 IMAP URL Scheme
 *
 ***************************************************************************/

#include "setup.h"

#ifndef CURL_DISABLE_IMAP

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t unsigned long
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "hostip.h"
#include "progress.h"
#include "transfer.h"
#include "escape.h"
#include "http.h" /* for HTTP proxy tunnel stuff */
#include "socks.h"
#include "imap.h"

#include "strtoofft.h"
#include "strequal.h"
#include "sslgen.h"
#include "connect.h"
#include "strerror.h"
#include "select.h"
#include "multiif.h"
#include "url.h"
#include "rawstr.h"
#include "strtoofft.h"
#include "http_proxy.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Local API functions */
static CURLcode imap_parse_url_path(struct connectdata *conn);
static CURLcode imap_regular_transfer(struct connectdata *conn, bool *done);
static CURLcode imap_do(struct connectdata *conn, bool *done);
static CURLcode imap_done(struct connectdata *conn,
                          CURLcode, bool premature);
static CURLcode imap_connect(struct connectdata *conn, bool *done);
static CURLcode imap_disconnect(struct connectdata *conn, bool dead);
static CURLcode imap_multi_statemach(struct connectdata *conn, bool *done);
static int imap_getsock(struct connectdata *conn,
                        curl_socket_t *socks,
                        int numsocks);
static CURLcode imap_doing(struct connectdata *conn,
                           bool *dophase_done);
static CURLcode imap_setup_connection(struct connectdata * conn);

static CURLcode imap_fetch(struct connectdata *conn);
static int imap_process_resp_ln(const char* idstr, const char* h,
                                size_t h_length,
                                const char* good, size_t* consumed);
/*static void hexprintf(const char* s, size_t ln, const char* desc);*/
static CURLcode imap_state_upgrade_tls(struct connectdata *conn);

/*
 * IMAP protocol handler.
 */

const struct Curl_handler Curl_handler_imap = {
  "IMAP",                           /* scheme */
  imap_setup_connection,            /* setup_connection */
  imap_do,                          /* do_it */
  imap_done,                        /* done */
  ZERO_NULL,                        /* do_more */
  imap_connect,                     /* connect_it */
  imap_multi_statemach,             /* connecting */
  imap_doing,                       /* doing */
  imap_getsock,                     /* proto_getsock */
  imap_getsock,                     /* doing_getsock */
  ZERO_NULL,                        /* perform_getsock */
  imap_disconnect,                  /* disconnect */
  ZERO_NULL,                        /* readwrite */
  PORT_IMAP,                        /* defport */
  CURLPROTO_IMAP,                   /* protocol */
  PROTOPT_CLOSEACTION | PROTOPT_NEEDSPWD /* flags */
};


#ifdef USE_SSL
/*
 * IMAPS protocol handler.
 */

const struct Curl_handler Curl_handler_imaps = {
  "IMAPS",                          /* scheme */
  imap_setup_connection,            /* setup_connection */
  imap_do,                          /* do_it */
  imap_done,                        /* done */
  ZERO_NULL,                        /* do_more */
  imap_connect,                     /* connect_it */
  imap_multi_statemach,             /* connecting */
  imap_doing,                       /* doing */
  imap_getsock,                     /* proto_getsock */
  imap_getsock,                     /* doing_getsock */
  ZERO_NULL,                        /* perform_getsock */
  imap_disconnect,                  /* disconnect */
  ZERO_NULL,                        /* readwrite */
  PORT_IMAPS,                       /* defport */
  CURLPROTO_IMAP | CURLPROTO_IMAPS, /* protocol */
  PROTOPT_CLOSEACTION | PROTOPT_SSL | PROTOPT_NEEDSPWD /* flags */
};
#endif

#ifndef CURL_DISABLE_HTTP
/*
 * HTTP-proxyed IMAP protocol handler.
 */

static const struct Curl_handler Curl_handler_imap_proxy = {
  "IMAP",                               /* scheme */
  ZERO_NULL,                            /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_IMAP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};


#ifdef USE_SSL
/*
 * HTTP-proxyed IMAPS protocol handler.
 */

static const struct Curl_handler Curl_handler_imaps_proxy = {
  "IMAPS",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_IMAPS,                           /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};
#endif
#endif


/**
 * write text to output file
 */
/*
#define imap_log(conn, pp, hdr, msg) _imap_log(conn, pp, hdr, msg,\
                 __FILE__, __LINE__, __FUNCTION__)
static void _imap_log(struct connectdata* conn,
                      struct pingpong* pp, const char* hdr, const char* msg,
                      const char* file, int ln, const char* method) {
  char buf[512];
  snprintf(buf, sizeof(buf), "\nLOG: %s:%i(%s) msg: %s hdr: %s\n"
           "  cache-len: %i nread_resp: %i ###\n\n",
           file, ln, method, msg, hdr, pp?pp->cache_size:0xFFFFFFFF,
           pp?pp->nread_resp:0xFFFFFFFF);
  buf[sizeof(buf)-1] = 0;
  printf("%s", buf);
  fflush(stdout);
  (void)conn;
  // Curl_client_write(conn, CLIENTWRITE_BODY, buf, strlen(buf));
}
*/

/***********************************************************************
 *
 * imapsendf()
 *
 * Sends the formated string as an IMAP command to a server
 *
 * Designed to never block.
 */
static CURLcode imapsendf(struct connectdata *conn,
                          const char *idstr, /* id to wait for at the
                                                completion of this command */
                          const char *fmt, ...)
{
  CURLcode res;
  struct imap_conn *imapc = &conn->proto.imapc;
  va_list ap;

  /*imap_log(conn, NULL, fmt, idstr);*/

  va_start(ap, fmt);

  if(idstr)
    imapc->idstr = idstr; /* this is the thing */

  res = Curl_pp_vsendf(&imapc->pp, fmt, ap);

  va_end(ap);

  return res;
}

static const char *getcmdid(struct connectdata *conn)
{
  static const char * const ids[]= {
    "A",
    "B",
    "C",
    "D"
  };

  struct imap_conn *imapc = &conn->proto.imapc;

  /* get the next id, but wrap at end of table */
  imapc->cmdid = (int)((imapc->cmdid+1) % (sizeof(ids)/sizeof(ids[0])));

  return ids[imapc->cmdid];
}

/* For the IMAP "protocol connect" and "doing" phases only */
static int imap_getsock(struct connectdata *conn,
                        curl_socket_t *socks,
                        int numsocks)
{
  return Curl_pp_getsock(&conn->proto.imapc.pp, socks, numsocks);
}

/* function that checks for an imap status code at the start of the
   given string */
static int imap_endofresp(struct pingpong *pp, int *resp)
{
  char *line = pp->linestart_resp;
  size_t len = pp->nread_resp;
  struct imap_conn *imapc = &pp->conn->proto.imapc;
  const char *id = imapc->idstr;
  size_t id_len = strlen(id);

  if(len >= id_len + 3) {
    if(!memcmp(id, line, id_len) && (line[id_len] == ' ') ) {
      /* end of response */
      *resp = line[id_len+1]; /* O, N or B */
      return TRUE;
    }
    else if(((imapc->state == IMAP_LIST) ||
             (imapc->state == IMAP_SEARCH) ||
             (imapc->state == IMAP_FETCH_HEADER) ||
             (imapc->state == IMAP_FETCH_BODY)) &&
            !memcmp("* ", line, 2) ) {
      /* FETCH response we're interested in */
      *resp = '*';
      return TRUE;
    }
  }
  return FALSE; /* nothing for us */
}


#define state(a, b) _state(a, b, __FILE__, __LINE__)

/* This is the ONLY way to change IMAP state! */
static void _state(struct connectdata *conn,
                  imapstate newstate, const char* file, int ln)
{
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  /* for debug purposes */
  static const char * const names[]={
    "STOP",
    "SERVERGREET",
    "LOGIN",
    "STARTTLS",
    "LIST",
    "SEARCH",
    "UPGRADETLS",
    "SELECT",
    "FETCH_HEADER",
    "FETCH_BODY",
    "LOGOUT",
    /* LAST */
  };
#endif
  struct imap_conn *imapc = &conn->proto.imapc;
  (void)file; /* these *MAY* be un-used, this keeps compiler happy */
  (void)ln;

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  if(imapc->state != newstate) {
    infof(conn->data, "IMAP %p state change from %s to %s\n",
          imapc, names[imapc->state], names[newstate]);
    /*printf("IMAP %p state change from %s to %s  %s:%i\n",
             imapc, names[imapc->state], names[newstate], file, ln);*/
  }
#endif
  imapc->state = newstate;
}

static CURLcode imap_state_login(struct connectdata *conn)
{
  CURLcode result;
  struct FTP *imap = conn->data->state.proto.imap;
  const char *str;

  str = getcmdid(conn);

  /* send USER and password */
  result = imapsendf(conn, str, "%s LOGIN %s %s", str,
                     imap->user?imap->user:"",
                     imap->passwd?imap->passwd:"");
  if(result)
    return result;

  state(conn, IMAP_LOGIN);

  return CURLE_OK;
}

#ifdef USE_SSL
static void imap_to_imaps(struct connectdata *conn)
{
  conn->handler = &Curl_handler_imaps;
}
#else
#define imap_to_imaps(x) Curl_nop_stmt
#endif

/* for STARTTLS responses */
static CURLcode imap_state_starttls_resp(struct connectdata *conn,
                                         int imapcode,
                                         imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; /* no use for this yet */

  if(imapcode != 'O') {
    failf(data, "STARTTLS denied. %c", imapcode);
    result = CURLE_LOGIN_DENIED;
  }
  else {
    if(data->state.used_interface == Curl_if_multi) {
      state(conn, IMAP_UPGRADETLS);
      return imap_state_upgrade_tls(conn);
    }
    else {
      result = Curl_ssl_connect(conn, FIRSTSOCKET);
      if(CURLE_OK == result) {
        imap_to_imaps(conn);
        result = imap_state_login(conn);
      }
    }
  }
  state(conn, IMAP_STOP);
  return result;
}

static CURLcode imap_state_upgrade_tls(struct connectdata *conn)
{
  struct imap_conn *imapc = &conn->proto.imapc;
  CURLcode result;

  result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &imapc->ssldone);

  if(imapc->ssldone) {
    imap_to_imaps(conn);
    result = imap_state_login(conn);
    state(conn, IMAP_STOP);
  }

  return result;
}

/* for LOGIN responses */
static CURLcode imap_state_login_resp(struct connectdata *conn,
                                      int imapcode,
                                      imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  (void)instate; /* no use for this yet */

  if(imapcode != 'O') {
    failf(data, "Access denied. %c", imapcode);
    result = CURLE_LOGIN_DENIED;
  }

  state(conn, IMAP_STOP);
  return result;
}

/* for the (first line of) FETCH BODY[HEADER/TEXT] response */
static CURLcode imap_state_fetch_gen_body_resp(struct connectdata *conn,
                                               int imapcode,
                                               imapstate instate,
                                               bool is_body)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  char *ptr = data->state.buffer;
  size_t buflen = strlen(ptr);
  struct imap_conn *imapc = &conn->proto.imapc;
  struct FTP *imap = data->state.proto.imap;
  struct pingpong *pp = &imapc->pp;
  int got_eor = 0;
  (void)instate; /* no use for this yet */

  /*imap_log(conn, pp, ptr, "enter");
    printf("cache: %s\n", pp->cache?pp->cache:"NULL");*/

  /* If header doesn't end in a newline, but does end in a \r, then add
   * a newline to make parsing easier.
   */
  if(ptr[buflen-1] == '\r') {
    ptr[buflen] = '\n';
    buflen++;
    ptr[buflen] = 0;
  }

  if('*' != imapcode) {
    Curl_pgrsSetDownloadSize(data, 0);
    if(imap_process_resp_ln(imapc->idstr, ptr,
                            buflen, "BAD", NULL))
      result = CURLE_REMOTE_FILE_NOT_FOUND;
    else
      /* who knows */
      result = CURLE_OK;
    goto end_of_response;
  }

  /* Something like this comes
   *     "* 1 FETCH (FLAGS (\Seen) BODY[HEADER] {482}\r"
   * Or: "* 1 FETCH (BODY[TEXT] {2021}\r"
   */
  while(*ptr && (*ptr != '{'))
    ptr++;

  if(*ptr == '{') {
    size_t chunk= pp->cache_size;

    curl_off_t filesize = curlx_strtoofft(ptr+1, NULL, 10);
    if(filesize)
      Curl_pgrsSetDownloadSize(data, filesize);

    /*printf("hdr-ptr: %p chunk: %i  filesize: %i -:%s:-\n",
             ptr, (int)(chunk), (int)(filesize), ptr);*/

    /* header is consumed, zero it out and process cache */
    data->state.buffer[0] = 0;

    /* Do note that there may even be additional "headers" after the body. */

    if(chunk > (size_t)filesize)
      /* the conversion from curl_off_t to size_t is always fine here */
      chunk = (size_t)filesize;

    if(chunk) {
      result = Curl_client_write(conn, CLIENTWRITE_BODY, pp->cache, chunk);

      if(result)
        return result;

      filesize -= chunk;
    }

    if(filesize == 0) {
      /* Seems there is a closing ")\r\n" on the end of entries...eat this if
       * it exists.
       */
      if(pp->cache_size >= chunk +3) {
        if((pp->cache[chunk] == ')') &&
            (pp->cache[chunk+1] == '\r') &&
            (pp->cache[chunk+2] == '\n'))
          chunk += 3;
      }
    }

    /*printf("after check for \\r\\n), cache-size: %i  chunk: %i"
             "  filesize: %i\n",
             (int)(pp->cache_size), (int)(chunk), (int)(filesize));*/

    /* we've now used parts of or the entire cache */
    if(pp->cache_size > chunk) {
      /* See if we have the response code..if so, we are done, else, keep
       * at it.
       */

      /*printf("chunk: %i cache_size: %i -:%s:-\n",
               chunk, pp->cache_size, pp->cache+chunk);
      hexprintf(pp->cache + chunk, 10, "before header check");*/

      if(pp->cache[chunk] && pp->cache[chunk] != '*') {
        size_t orig_chunk = chunk;
        if(imap_process_resp_ln(imapc->idstr, pp->cache + chunk,
                                pp->cache_size - chunk, "OK", &chunk)) {
          got_eor = 1; /* response is good */
          /*imap_log(conn, NULL, pp->cache + chunk,
            "response is good, has newline");*/
        }
        else {
          if(chunk != orig_chunk) {
            /*imap_log(conn, NULL, pp->cache + chunk,
              "found newline, but had bad response. TODO: Tell user.");*/
            got_eor = 1;
          }
          /*else {
            imap_log(conn, NULL, pp->cache + chunk,
                     "no newline, bad response. TODO: Tell user.");
          }*/
        }
      }
    }

    if(chunk < pp->cache_size) {
      /* part of, move the trailing data to the start and reduce the size */
      memmove(pp->cache, pp->cache+chunk,
              pp->cache_size - chunk);
      pp->cache_size -= chunk;
      pp->cache[pp->cache_size] = 0; /* null terminate */
    }
    else {
      free(pp->cache);
      pp->cache = NULL;
      pp->cache_size = 0;
    }

    /*printf("filesize: %i\n", (int)(filesize));*/

    data->req.maxdownload = filesize;
    if(!filesize)
      /* the entire data is already transferred! */
      Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    else {
      /*printf("Starting download, filesize: %i\n", (int)(filesize));*/
      /* IMAP download */
      Curl_setup_transfer(conn, FIRSTSOCKET, filesize, FALSE,
                          imap->bytecountp,
                          -1, NULL); /* no upload here */
      Curl_do_transfer(conn);
    }
  }
  else {
    /* We don't know how to parse this line */
    result = CURLE_FTP_WEIRD_SERVER_REPLY; /* TODO: fix this code */
  }

  if(got_eor) {
    end_of_response:
    if(is_body)
      state(conn, IMAP_STOP);
    else {
      /* Download the body of the email when we are done with headers. */
      imap_fetch(conn);
    }
  }
  return result;
}

/* for the (first line of) FETCH BODY[TEXT] response */
static CURLcode imap_state_fetch_resp(struct connectdata *conn,
                                      int imapcode,
                                      imapstate instate)
{
  return imap_state_fetch_gen_body_resp(conn, imapcode, instate, true);
}

/* for the (first line of) FETCH BODY[HEADER] response */
static CURLcode imap_state_fetch_hdr_resp(struct connectdata *conn,
                                          int imapcode,
                                          imapstate instate)
{
  return imap_state_fetch_gen_body_resp(conn, imapcode, instate, false);
}

/* Grabs lines until we find a line that does NOT start with 'starts'.  Returns
 * length in bytes.
 */
static size_t get_until_nstarts(const char* str, size_t max,
                                const char* starts)
{
  size_t i;
  size_t slen = strlen(starts);
  /* Grab lines until done with all 'starts' elements */
  for(i = 0; i<max; i++) {
    if(strncmp((str + i), starts, slen) == 0) {
      /* grab entire line */
      i += slen;
      for(; i< max; i++) {
        if(str[i] == '\n') {
          break;
        }
      }
    }
    else {
      break;
    }
  }
  return i;
}

#if 0
/** Returns next instance of 'n', with case-insensitive search.  If
 * consumed is not NULL, then this will only search to the first newline
 * and 'consumed' will be increased by the number of bytes it takes to
 * consume the entire line, newline included.
 */
static const char* imap_strcasestr_ln(const char* h, const char* n,
                                      size_t* consumed)
{
  size_t lnh = strlen(h);
  size_t lnn = strlen(n);
  size_t i;
  for(i = 0; i<lnh - lnn; i++) {
    if(strncasecmp(h+i, n, lnn) == 0) {
      if(consumed) {
        *consumed = i + lnn;
        for(; *consumed<lnh; (*consumed)++) {
          if(h[*consumed] == '\n')
            break;
        }
      }
      return h+i;
    }
  }
  return NULL;
}
#endif

/** Returns 1 if we find expected response, 0 otherwise.
 * If newline is not found, then we return 0 and consume nothing.
 */
static int imap_process_resp_ln(const char* idstr, const char* h,
                                size_t lnh,
                                const char* good, size_t* consumed)
{
  size_t lng = strlen(good);
  size_t i;
  size_t lni = strlen(idstr);
  int rv = 1;

  /* If there is no newline, then return 0 w/out consuming anything. */
  for(i = 0; i<lnh; i++) {
    if(h[i] == '\n')
      break;
  }
  if(i == lnh)
    return 0; /* didn't find newline, don't consume anything */

  for(i = 0; i<lnh - lng; i++) {
    /* skip any leading whitespace */
    if(!ISSPACE(h[i]))
      break;
  }

  if(strncmp(h+i, idstr, lni) == 0) {
    i += lni;
    if(!ISSPACE(h[i])) {
      rv = 0;; /* should be a space after idstr, otherwise not a real match */
      goto out_consume;
    }

    /* walk over space */
    for(; i<lnh - lng; i++) {
      if(!ISSPACE(h[i]))
        break;
    }

    /* Next token is response.  Make sure it matches expected.  Assume
     * case-insensitive match is OK.
     */
    if(! Curl_raw_nequal(h+i, good, lng))
      rv = 0; /* didn't match expected response */
  }
  else
    rv = 0; /* didn't match id str */

out_consume:
  for(; i<lnh; i++) {
    if(h[i] == '\n') {
      i++;
      if(consumed)
        *consumed += i;
      break;
    }
  }
  return rv;
}

/*
static void hexprintf(const char* s, size_t ln, const char* desc) {
  size_t i;
  printf("%s: ", desc);
  for(i = 0; i<ln; i++) {
    if(i % 16 == 15)
      printf("%02hx\n", (unsigned short)(s[i]));
    else
      printf("%02hx ", (unsigned short)(s[i]));
  }
  printf("\n\n");
}
*/

/* for the LIST response */
static CURLcode imap_state_gen_listing_resp(struct connectdata *conn,
                                            const char* list_str,
                                            int imapcode,
                                            imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct FTP *imap = data->state.proto.imap;
  struct pingpong *pp = &imapc->pp;
  char *ptr = data->state.buffer;
  size_t buflen = strlen(ptr);
  size_t i;
  int got_eor = 0;
  (void)instate; /* no use for this yet */

  /*imap_log(conn, pp, ptr, "enter");*/

  /* If header doesn't end in a newline, but does end in a \r, then add
   * a newline to make parsing easier.
   */
  if(ptr[buflen-1] == '\r') {
    ptr[buflen] = '\n';
    buflen++;
    ptr[buflen] = 0;
  }

  if(('*' != imapcode) || (strncmp(ptr, list_str, strlen(list_str)) != 0)) {
    Curl_pgrsSetDownloadSize(data, 0);
    state(conn, IMAP_STOP);
    return CURLE_OK;
  }

  /*printf("ptr: -:%s:-  buflen: %i\n", ptr, (int)(buflen));
  hexprintf(ptr, buflen, "header on entry");*/

  /* Header is single line, something like this:
   *       * LIST (\Flags) "/" "INBOX"
   *  or   * SEARCH [uid-list]
   */

  result = Curl_client_write(conn, CLIENTWRITE_BODY, ptr, buflen);
  data->state.buffer[0] = 0;

  if(pp->cache) {
    /* At this point there is a bunch of data in the header "cache" that is
       actually body content, send it as body and then skip it. Do note
       that there may even be additional "headers" after the body. */

    /*hexprintf(pp->cache, pp->cache_size, "pp->cache");*/

    i = get_until_nstarts(pp->cache, pp->cache_size, list_str);

    /*printf("i: %i  cache_size: %i\n", (int)(i), (int)(pp->cache_size));
      hexprintf(pp->cache, i, "cache to consume");*/

    if(i) {
      result = Curl_client_write(conn, CLIENTWRITE_BODY, pp->cache, i);
      if(result)
        return result;
    }

    /* we've now used parts of or the entire cache */
    if(pp->cache_size > i) {
      size_t orig_i = i;
      if(imap_process_resp_ln(imapc->idstr, pp->cache + i,
                              pp->cache_size - i, "OK", &i)) {
        /*printf("got eor, sz: %i  i: %i orig_i: %i\n",
                 (int)(pp->cache_size), (int)(i), (int)(orig_i));*/
        got_eor = 1; /* response is good */
      }
      else {
        if(i != orig_i) {
          /*printf("found newline, but had bad response, sz: %i  i: %i"
                   " orig_i: %i\n",
                   (int)(pp->cache_size), (int)(i), (int)(orig_i));*/
          /* found newline, but had bad response. TODO: Tell user. */
          got_eor = 1;
        }
        /*else {
          printf("didn't find newline, sz: %i  i: %i orig_i: %i\n",
                 (int)(pp->cache_size), (int)(i), (int)(orig_i));
        }*/
      }
    }

    if(pp->cache_size > i) {
      if(i) {
        /* part of, move the trailing data to the start and reduce the size */
        memmove(pp->cache, pp->cache+i, pp->cache_size - i);
        pp->cache_size -= i;
        pp->cache[pp->cache_size] = 0; /* ensure null term */
      }
    }
    else {
      /* cache is drained */
      free(pp->cache);
      pp->cache = NULL;
      pp->cache_size = 0;
    }

    /* Might should be case insensitive search ? */
    data->req.maxdownload = 0; /* no idea */
    if((!pp->cache) || got_eor) {
      /* printf("Completed, cache:\n%s\n", pp->cache?pp->cache:"NULL"); */
      /* the entire data is already transfered! */
      Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
    }
    else {
      /* TODO:  I don't think transfer logic can deal with this properly
       * because we don't know how much to read, and need to keep an eye out
       * for the end-of-response.
       */
      /* printf("NOT completed, cache:\n%s\n", pp->cache); */
      /* fflush(stdout); */
      /* IMAP download */
      Curl_setup_transfer(conn, FIRSTSOCKET, 0, FALSE,
                          imap->bytecountp,
                          -1, NULL); /* no upload here */
      Curl_do_transfer(conn);
    }
  }
  else
    /* We don't know how to parse this line */
    result = CURLE_FTP_WEIRD_SERVER_REPLY; /* TODO: fix this code */

  if(got_eor && !pp->cache) {
    /* TODO:  Assign rslts to uid and then go fetch it if user
     * prefers, otherwise stop.
     */
    state(conn, IMAP_STOP);
  }
  return result;
}

static CURLcode imap_state_list_resp(struct connectdata *conn,
                                     int imapcode,
                                     imapstate instate)
{
  return imap_state_gen_listing_resp(conn, "* LIST ", imapcode, instate);
}

/* for the SEARCH response */
static CURLcode imap_state_search_resp(struct connectdata *conn,
                                       int imapcode,
                                       imapstate instate)
{
  return imap_state_gen_listing_resp(conn, "* SEARCH ", imapcode, instate);
}

/* start the DO phase */
static CURLcode imap_listing(struct connectdata *conn, const char* lst_args)
{
  CURLcode result = CURLE_OK;
  const char *str;

  str = getcmdid(conn);

  result = imapsendf(conn, str, "%s LIST \"\" \"%s\"", str, lst_args);
  if(result)
    return result;

  state(conn, IMAP_LIST);
  return result;
}

/* start the DO phase */
static CURLcode imap_search(struct connectdata *conn, const char* search_args)
{
  CURLcode result = CURLE_OK;
  const char *str;

  str = getcmdid(conn);

  result = imapsendf(conn, str, "%s SEARCH \"%s\"", str, search_args);
  if(result)
    return result;

  state(conn, IMAP_SEARCH);
  return result;
}

/* start the DO phase */
static CURLcode imap_select(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct imap_conn *imapc = &conn->proto.imapc;
  const char *str;

  str = getcmdid(conn);

  result = imapsendf(conn, str, "%s SELECT %s", str,
                     imapc->mbox?imapc->mbox:"");
  if(result)
    return result;

  state(conn, IMAP_SELECT);
  return result;
}

static CURLcode imap_fetch_hdr(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const char *str;

  str = getcmdid(conn);

  result = imapsendf(conn, str, "%s FETCH %s BODY[HEADER]",
                     str, conn->proto.imapc.uid);
  if(result)
    return result;

  /*
   * When issued, the server will respond with a single line similar to
   * '* 1 FETCH (BODY[TEXT] {2021}'
   *
   * Identifying the fetch and how many bytes of contents we can expect. We
   * must extract that number before continuing to "download as usual".
   */

  state(conn, IMAP_FETCH_HEADER);
  return result;
}

static CURLcode imap_fetch(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const char *str;

  str = getcmdid(conn);

  result = imapsendf(conn, str, "%s FETCH %s BODY[TEXT]",
                     str, conn->proto.imapc.uid);
  if(result)
    return result;

  /*
   * When issued, the server will respond with a single line similar to
   * '* 1 FETCH (BODY[TEXT] {2021}'
   *
   * Identifying the fetch and how many bytes of contents we can expect. We
   * must extract that number before continuing to "download as usual".
   */

  state(conn, IMAP_FETCH_BODY);
  return result;
}

/* for SELECT responses */
static CURLcode imap_state_select_resp(struct connectdata *conn,
                                       int imapcode,
                                       imapstate instate)
{
  CURLcode result = CURLE_OK;
  struct SessionHandle *data = conn->data;
  struct imap_conn *imapc = &conn->proto.imapc;
  (void)instate; /* no use for this yet */

  if(imapcode != 'O') {
    failf(data, "Select failed");
    result = CURLE_LOGIN_DENIED;
  }
  else {
    /* If we have a search defined, run the search..else attempt a fetch */
    if(imapc->search && imapc->search[0])
      imap_search(conn, imapc->search);
    else {
      if(imapc->uid && imapc->uid[0]) {
        if(data->set.include_header)
          result = imap_fetch_hdr(conn);
        else
          result = imap_fetch(conn);
      }
      else
        state(conn, IMAP_STOP);
    }
  }
  return result;
}

static CURLcode imap_statemach_act(struct connectdata *conn)
{
  CURLcode result;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data=conn->data;
  int imapcode;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct pingpong *pp = &imapc->pp;
  size_t nread = 0;
  size_t last_tot;

  /*imap_log(conn, pp, data->state.buffer, "enter");*/

  /* busy upgrading the connection; right now all I/O is SSL/TLS, not IMAP */
  if(imapc->state == IMAP_UPGRADETLS)
    return imap_state_upgrade_tls(conn);

  if(pp->sendleft)
    return Curl_pp_flushsend(pp);

  /* we read a piece of response */
  result = Curl_pp_readresp(sock, pp, &imapcode, &nread);
  if(result)
    return result;

  /*imap_log(conn, pp, data->state.buffer, "after-pp-readresp");*/

  if(imapcode) {
    /* we have now received at least first line of an IMAP server response */
    last_tot = strlen(data->state.buffer) + pp->cache_size;
    while(true) {
      switch(imapc->state) {
      case IMAP_SERVERGREET:
        if(imapcode != 'O') {
          failf(data, "Got unexpected imap-server response");
          return CURLE_FTP_WEIRD_SERVER_REPLY;
        }

        if(data->set.ftp_ssl && !conn->ssl[FIRSTSOCKET].use) {
          /* We don't have a SSL/TLS connection yet, but SSL is requested.
             Switch to TLS connection now */
          const char *str;

          str = getcmdid(conn);
          result = imapsendf(conn, str, "%s STARTTLS", str);
          state(conn, IMAP_STARTTLS);
        }
        else
          result = imap_state_login(conn);
        if(result)
          return result;
        break;

      case IMAP_LOGIN:
        result = imap_state_login_resp(conn, imapcode, imapc->state);
        break;

      case IMAP_STARTTLS:
        result = imap_state_starttls_resp(conn, imapcode, imapc->state);
        break;

      case IMAP_FETCH_HEADER:
        result = imap_state_fetch_hdr_resp(conn, imapcode, imapc->state);
        break;

      case IMAP_FETCH_BODY:
        result = imap_state_fetch_resp(conn, imapcode, imapc->state);
        break;

      case IMAP_SELECT:
        result = imap_state_select_resp(conn, imapcode, imapc->state);
        break;

      case IMAP_LIST:
        result = imap_state_list_resp(conn, imapcode, imapc->state);
        break;

      case IMAP_SEARCH:
        result = imap_state_search_resp(conn, imapcode, imapc->state);
        break;

      case IMAP_LOGOUT:
        /* fallthrough, just stop! */
      default:
        /* internal error */
        state(conn, IMAP_STOP);
        break;
      }/* switch */

      /*printf("done with switch, state: %i  result: %i cache_size: %i"
               "  last_tot: %i\n",
               imapc->state, result,(int)(pp->cache_size), (int)(last_tot));
      printf("state.buffer: %s\n  cache: %s\n",
             data->state.buffer, pp->cache?pp->cache:"NULL");
      fflush(stdout);*/

      /* If result is bad..bail out immediately */
      if(result != CURLE_OK)
        return result;

      /* If we have data left to be consumed, run the state machine again */
      if((imapc->state == IMAP_FETCH_HEADER) ||
         (imapc->state == IMAP_FETCH_BODY) ||
         (imapc->state == IMAP_LIST) ||
         (imapc->state == IMAP_SEARCH)) {
        size_t this_tot = pp->cache_size;
        size_t to_move = 0;
        while(true) {
          if(to_move >= pp->cache_size)
            break;
          if(pp->cache[to_move] == '\n') {
            to_move++;
            break;
          }
          to_move++;
        }

        if((!to_move)
           || ((to_move == pp->cache_size) && (pp->cache[to_move-1] != '\n')))
          break;

        if(this_tot == last_tot) {
          /*printf("no progress, breaking out of loop\n");
            fflush(stdout);*/
          /* appear to be making no progress progress..bail out of loop */
          break;
        }

        /* Merge cache into header */
        if(to_move > BUFSIZE) {
          /*printf("ERROR:  to_move: %i > BUFSIZE: %i\n",
                   (int)(to_move), BUFSIZE);*/
          to_move = BUFSIZE;
        }

        /*printf("to-move: %i\n", (int)(to_move));
          fflush(stdout);*/

        if(to_move > 0) {
          memcpy(data->state.buffer, pp->cache, to_move);
          data->state.buffer[to_move] = 0;

          if(to_move < pp->cache_size) {
            memmove(pp->cache, pp->cache+to_move, pp->cache_size - to_move);
            pp->cache_size -= to_move;
            pp->cache[pp->cache_size] = 0;
          }
          else {
            free(pp->cache);
            pp->cache = NULL;
            pp->cache_size = 0;
          }
        }

        /*printf("state: %i  cache_size: %i  last_tot: %i\n",
                 imapc->state, (int)(pp->cache_size), (int)(last_tot));
        fflush(stdout);*/

        last_tot = this_tot;
      }
      else
        break;
    }/* while */
  }/* if imap code */
  /*imap_log(conn, pp, data->state.buffer, "done");*/

  return result;
}

/* called repeatedly until done from multi.c */
static CURLcode imap_multi_statemach(struct connectdata *conn,
                                         bool *done)
{
  struct imap_conn *imapc = &conn->proto.imapc;
  CURLcode result;

  if((conn->handler->flags & PROTOPT_SSL) && !imapc->ssldone)
    result = Curl_ssl_connect_nonblocking(conn, FIRSTSOCKET, &imapc->ssldone);
  else
    result = Curl_pp_multi_statemach(&imapc->pp);

  *done = (imapc->state == IMAP_STOP) ? TRUE : FALSE;

  return result;
}

static CURLcode imap_easy_statemach(struct connectdata *conn)
{
  struct imap_conn *imapc = &conn->proto.imapc;
  struct pingpong *pp = &imapc->pp;
  CURLcode result = CURLE_OK;

  while(imapc->state != IMAP_STOP) {
    result = Curl_pp_easy_statemach(pp);
    if(result)
      break;
  }

  return result;
}

/*
 * Allocate and initialize the struct IMAP for the current SessionHandle.  If
 * need be.
 */
static CURLcode imap_init(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  struct FTP *imap = data->state.proto.imap;
  if(!imap) {
    imap = data->state.proto.imap = calloc(sizeof(struct FTP), 1);
    if(!imap)
      return CURLE_OUT_OF_MEMORY;
  }

  /* get some initial data into the imap struct */
  imap->bytecountp = &data->req.bytecount;

  /* No need to duplicate user+password, the connectdata struct won't change
     during a session, but we re-init them here since on subsequent inits
     since the conn struct may have changed or been replaced.
  */
  imap->user = conn->user;
  imap->passwd = conn->passwd;

  return CURLE_OK;
}

/*
 * imap_connect() should do everything that is to be considered a part of
 * the connection phase.
 *
 * The variable 'done' points to will be TRUE if the protocol-layer connect
 * phase is done when this function returns, or FALSE is not. When called as
 * a part of the easy interface, it will always be TRUE.
 */
static CURLcode imap_connect(struct connectdata *conn,
                                 bool *done) /* see description above */
{
  CURLcode result;
  struct imap_conn *imapc = &conn->proto.imapc;
  struct SessionHandle *data=conn->data;
  struct pingpong *pp = &imapc->pp;

  *done = FALSE; /* default to not done yet */

  /* If there already is a protocol-specific struct allocated for this
     sessionhandle, deal with it */
  Curl_reset_reqproto(conn);

  result = imap_init(conn);
  if(CURLE_OK != result)
    return result;

  /* We always support persistent connections on imap */
  conn->bits.close = FALSE;

  pp->response_time = RESP_TIMEOUT; /* set default response time-out */
  pp->statemach_act = imap_statemach_act;
  pp->endofresp = imap_endofresp;
  pp->conn = conn;

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy) {
    /* for IMAP over HTTP proxy */
    struct HTTP http_proxy;
    struct FTP *imap_save;

    /* BLOCKING */
    /* We want "seamless" IMAP operations through HTTP proxy tunnel */

    /* Curl_proxyCONNECT is based on a pointer to a struct HTTP at the member
     * conn->proto.http; we want IMAP through HTTP and we have to change the
     * member temporarily for connecting to the HTTP proxy. After
     * Curl_proxyCONNECT we have to set back the member to the original struct
     * IMAP pointer
     */
    imap_save = data->state.proto.imap;
    memset(&http_proxy, 0, sizeof(http_proxy));
    data->state.proto.http = &http_proxy;

    result = Curl_proxyCONNECT(conn, FIRSTSOCKET,
                               conn->host.name, conn->remote_port);

    data->state.proto.imap = imap_save;

    if(CURLE_OK != result)
      return result;
  }

  if((conn->handler->flags & PROTOPT_SSL) &&
     data->state.used_interface != Curl_if_multi) {
    /* BLOCKING */
    result = Curl_ssl_connect(conn, FIRSTSOCKET);
    if(result)
      return result;
  }

  Curl_pp_init(pp); /* init generic pingpong data */

  /* When we connect, we start in the state where we await the server greeting
     response */
  state(conn, IMAP_SERVERGREET);
  imapc->idstr = "*"; /* we start off waiting for a '*' response */

  if(data->state.used_interface == Curl_if_multi)
    result = imap_multi_statemach(conn, done);
  else {
    result = imap_easy_statemach(conn);
    if(!result)
      *done = TRUE;
  }

  return result;
}

/***********************************************************************
 *
 * imap_done()
 *
 * The DONE function. This does what needs to be done after a single DO has
 * performed.
 *
 * Input argument is already checked for validity.
 */
static CURLcode imap_done(struct connectdata *conn, CURLcode status,
                          bool premature)
{
  struct SessionHandle *data = conn->data;
  struct FTP *imap = data->state.proto.imap;
  CURLcode result=CURLE_OK;
  (void)premature;

  if(!imap)
    /* When the easy handle is removed from the multi while libcurl is still
     * trying to resolve the host name, it seems that the imap struct is not
     * yet initialized, but the removal action calls Curl_done() which calls
     * this function. So we simply return success if no imap pointer is set.
     */
    return CURLE_OK;

  if(status) {
    conn->bits.close = TRUE; /* marked for closure */
    result = status;      /* use the already set error code */
  }

  /* clear these for next connection */
  imap->transfer = FTPTRANSFER_BODY;

  return result;
}

/***********************************************************************
 *
 * imap_perform()
 *
 * This is the actual DO function for IMAP. Get a file/directory according to
 * the options previously setup.
 */

static
CURLcode imap_perform(struct connectdata *conn,
                     bool *connected,  /* connect status after PASV / PORT */
                     bool *dophase_done)
{
  /* this is IMAP and no proxy */
  CURLcode result=CURLE_OK;

  DEBUGF(infof(conn->data, "DO phase starts\n"));

  if(conn->data->set.opt_no_body) {
    /* requested no body means no transfer... */
    struct FTP *imap = conn->data->state.proto.imap;
    imap->transfer = FTPTRANSFER_INFO;
  }

  *dophase_done = FALSE; /* not done yet */

  if(conn->proto.imapc.mbox && conn->proto.imapc.mbox[0]) {
    /* start the first command in the DO phase */
    result = imap_select(conn);
  }
  else {
    /* Just a listing then */
    result = imap_listing(conn, "*");
  }

  if(result)
    return result;

  /* run the state-machine */
  if(conn->data->state.used_interface == Curl_if_multi)
    result = imap_multi_statemach(conn, dophase_done);
  else {
    result = imap_easy_statemach(conn);
    *dophase_done = TRUE; /* with the easy interface we are done here */
  }
  *connected = conn->bits.tcpconnect[FIRSTSOCKET];

  if(*dophase_done)
    DEBUGF(infof(conn->data, "DO phase is complete\n"));

  return result;
}

/***********************************************************************
 *
 * imap_do()
 *
 * This function is registered as 'curl_do' function. It decodes the path
 * parts etc as a wrapper to the actual DO function (imap_perform).
 *
 * The input argument is already checked for validity.
 */
static CURLcode imap_do(struct connectdata *conn, bool *done)
{
  CURLcode retcode = CURLE_OK;

  *done = FALSE; /* default to false */

  /*
    Since connections can be re-used between SessionHandles, this might be a
    connection already existing but on a fresh SessionHandle struct so we must
    make sure we have a good 'struct IMAP' to play with. For new connections,
    the struct IMAP is allocated and setup in the imap_connect() function.
  */
  Curl_reset_reqproto(conn);
  retcode = imap_init(conn);
  if(retcode)
    return retcode;

  retcode = imap_parse_url_path(conn);
  if(retcode)
    return retcode;

  retcode = imap_regular_transfer(conn, done);

  return retcode;
}

/***********************************************************************
 *
 * imap_logout()
 *
 * This should be called before calling sclose().  We should then wait for the
 * response from the server before returning. The calling code should then try
 * to close the connection.
 *
 */
static CURLcode imap_logout(struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  const char *str;

  str = getcmdid(conn);

  result = imapsendf(conn, str, "%s LOGOUT", str, NULL);
  if(result)
    return result;
  state(conn, IMAP_LOGOUT);

  result = imap_easy_statemach(conn);

  return result;
}

/***********************************************************************
 *
 * imap_disconnect()
 *
 * Disconnect from an IMAP server. Cleanup protocol-specific per-connection
 * resources. BLOCKING.
 */
static CURLcode imap_disconnect(struct connectdata *conn, bool dead_connection)
{
  struct imap_conn *imapc= &conn->proto.imapc;

  /* The IMAP session may or may not have been allocated/setup at this
     point! */
  if(!dead_connection && imapc->pp.conn)
    (void)imap_logout(conn); /* ignore errors on the LOGOUT */

  Curl_pp_disconnect(&imapc->pp);

  Curl_safefree(imapc->mbox);
  Curl_safefree(imapc->uid);
  Curl_safefree(imapc->validity);
  Curl_safefree(imapc->search);

  return CURLE_OK;
}

/***********************************************************************
 *
 * imap_parse_url_path()
 *
 * Parse the URL path into separate path components.
 *
 */
static CURLcode imap_parse_url_path(struct connectdata *conn)
{
  /* the imap struct is already inited in imap_connect() */
  struct imap_conn *imapc = &conn->proto.imapc;
  struct SessionHandle *data = conn->data;
  const char *path = data->state.path;
  const char* tmp, *tmp2;
  char* all_ue;
  int len;
  size_t tmpi;

  /* url decode the path and use this mailbox */
  all_ue = curl_easy_unescape(data, path, 0, &len);
  if(!all_ue)
    return CURLE_OUT_OF_MEMORY;

  imapc->mbox = NULL;
  imapc->uid = NULL;
  imapc->validity = NULL;
  imapc->search = NULL;
  /* Deal with a few different types of URLs
   * Download a particular mail:
   *   <imap://tester:passwd@minbari.example.org/gray-council/;uid=20/>
   * List un-read email:
   *   <imap://tester:passwd@minbari.example.org/gray-council/>
   * List all email ids.
   *   <imap://tester:passwd@minbari.example.org/gray-council/?ALL>
   * List all folders:
   *   <imap://tester:passwd@minbari.example.org/>
   */
  tmp = strstr(all_ue, "/;");
  if(tmp) {
    tmpi = (tmp - all_ue) + 1;
    imapc->mbox = malloc(tmpi);
    memcpy(imapc->mbox, all_ue, tmpi - 1);
    imapc->mbox[tmpi-1] = 0;

    /*printf("mbox -:%s:-\n", imapc->mbox);
      hexprintf(imapc->mbox, tmpi - 1, "mbox");*/

    /* look for options */
    while(true) {
      if(Curl_raw_nequal(tmp + 2, "uid=", 4)) {
        tmp += 6; /* move past /;uid= */
        tmp2 = strstr(tmp, "/;");
        if(tmp2) {
          tmpi = (tmp2 - tmp) + 1;
        }
        else {
          /* Rest of the line is the UID then */
          tmpi = strlen(tmp) + 1;
        }
        imapc->uid = malloc(tmpi);
        memcpy(imapc->uid, tmp, tmpi - 1);
        imapc->uid[tmpi-1] = 0;

        tmp += tmpi;
        if(tmp2)
          tmp += 2;
        else
          break;
      }
      if(Curl_raw_nequal(tmp + 2, "UIDVALIDITY=", 4)) {
        tmp += 14; /* move past /;UIDVALIDITY= */
        tmp2 = strstr(tmp, "/;");
        if(tmp2) {
          tmpi = (tmp2 - tmp) + 1;
        }
        else {
          /* Rest of the line is the UIDVALIDITY then */
          tmpi = strlen(tmp) + 1;
        }
        imapc->validity = malloc(tmpi);
        memcpy(imapc->validity, tmp, tmpi - 1);
        imapc->validity[tmpi-1] = 0;

        tmp += tmpi;
        if(tmp2)
          tmp += 2;
        else
          break;
      }
    }/* while */
  }
  else {
    /* maybe a query ? */
    tmp = strstr(all_ue, "?");
    if(tmp) {
      tmpi = (tmp - all_ue) + 1;
      imapc->mbox = malloc(tmpi);
      memcpy(imapc->mbox, all_ue, tmpi - 1);
      imapc->mbox[tmpi-1] = 0;

      tmp += 1; /* move past ? */
      tmpi = strlen(tmp) + 1;
      imapc->search = malloc(tmpi);
      memcpy(imapc->search, tmp, tmpi - 1);
      imapc->search[tmpi-1] = 0;
    }
    else {
      size_t ln;
      /* Assume they want listing of entire mbox and only specified mbox */
      imapc->mbox = all_ue;
      /* If it ends with /, get rid of that */
      ln = strlen(imapc->mbox);
      if(imapc->mbox[ln-1] == '/') {
        imapc->mbox[ln-1] = 0;
      }
      all_ue = NULL; /* don't free this */
      imapc->search = strdup("*");
    }
  }

  if(all_ue)
    free(all_ue);

  return CURLE_OK;
}

/* call this when the DO phase has completed */
static CURLcode imap_dophase_done(struct connectdata *conn,
                                  bool connected)
{
  struct FTP *imap = conn->data->state.proto.imap;
  (void)connected;

  if(imap->transfer != FTPTRANSFER_BODY)
    /* no data to transfer */
    Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

  return CURLE_OK;
}

/* called from multi.c while DOing */
static CURLcode imap_doing(struct connectdata *conn,
                               bool *dophase_done)
{
  CURLcode result;
  result = imap_multi_statemach(conn, dophase_done);

  if(*dophase_done) {
    result = imap_dophase_done(conn, FALSE /* not connected */);

    DEBUGF(infof(conn->data, "DO phase is complete\n"));
  }
  return result;
}

/***********************************************************************
 *
 * imap_regular_transfer()
 *
 * The input argument is already checked for validity.
 *
 * Performs all commands done before a regular transfer between a local and a
 * remote host.
 *
 */
static
CURLcode imap_regular_transfer(struct connectdata *conn,
                              bool *dophase_done)
{
  CURLcode result=CURLE_OK;
  bool connected=FALSE;
  struct SessionHandle *data = conn->data;
  data->req.size = -1; /* make sure this is unknown at this point */

  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, 0);
  Curl_pgrsSetDownloadSize(data, 0);

  result = imap_perform(conn,
                        &connected, /* have we connected after PASV/PORT */
                        dophase_done); /* all commands in the DO-phase done? */

  if(CURLE_OK == result) {

    if(!*dophase_done)
      /* the DO phase has not completed yet */
      return CURLE_OK;

    result = imap_dophase_done(conn, connected);
    if(result)
      return result;
  }

  return result;
}

static CURLcode imap_setup_connection(struct connectdata * conn)
{
  struct SessionHandle *data = conn->data;

  if(conn->bits.httpproxy && !data->set.tunnel_thru_httpproxy) {
    /* Unless we have asked to tunnel imap operations through the proxy, we
       switch and use HTTP operations only */
#ifndef CURL_DISABLE_HTTP
    if(conn->handler == &Curl_handler_imap)
      conn->handler = &Curl_handler_imap_proxy;
    else {
#ifdef USE_SSL
      conn->handler = &Curl_handler_imaps_proxy;
#else
      failf(data, "IMAPS not supported!");
      return CURLE_UNSUPPORTED_PROTOCOL;
#endif
    }
    /*
     * We explicitly mark this connection as persistent here as we're doing
     * IMAP over HTTP and thus we accidentally avoid setting this value
     * otherwise.
     */
    conn->bits.close = FALSE;
#else
    failf(data, "IMAP over http proxy requires HTTP support built-in!");
    return CURLE_UNSUPPORTED_PROTOCOL;
#endif
  }

  data->state.path++;   /* don't include the initial slash */

  return CURLE_OK;
}

#endif /* CURL_DISABLE_IMAP */
