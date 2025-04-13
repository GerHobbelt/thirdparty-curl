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

#ifdef HAVE_FCNTL_H
/* for open() */
#include <fcntl.h>
#endif

#include <sys/stat.h>

#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_msgs.h"
#include "tool_cb_wrt.h"
#include "tool_dirhie.h"
#include "tool_getenv.h"
#include "tool_operate.h"
#include "tool_doswin.h"
#include "escape.h"
#include "sendf.h" /* for infof function prototype */

#include "memdebug.h" /* keep this as LAST include */

#ifdef _WIN32
#include <direct.h>
#endif

#ifdef O_BINARY
#define CURL_O_BINARY O_BINARY
#else
#define CURL_O_BINARY 0
#endif
#ifdef _WIN32
#define OPENMODE S_IREAD | S_IWRITE
#else
#define OPENMODE S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
#endif

static const char* find_beyond_all(const char* s, const char* set)
{
    while (*set) {
        const char* p = strrchr(s, *set);
        if (p)
            s = p + 1;
        set++;
    }
    return s;
}

// Produce a filename extension based on the mimetype
// reported by the server response. As this bit can be adversarial as well, we keep our
// sanity about it by restricting the length of the extension.
static char *get_file_extension_for_response_content_type(const char* fname, struct per_transfer *per) {
    struct OperationConfig *config;

    DEBUGASSERT(per);
    config = per->config;
    DEBUGASSERT(config);

    CURL* curl = per->curl;
    DEBUGASSERT(curl);

    char* ctype = NULL;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ctype);

    // construct a sane extension from the mime type if the filename doesn't have a porper extension yet.
    if (ctype) {
        static const char* mime_categories[] = {
            "text",
            "image",
            "video",
            "audio",
            "application"
        };

        char new_ext[16] = "";

        // TODO: map known mime types, e.g. text/javascript, to extension, without using the heuristic code below.

        for (int i = 0; i < sizeof(mime_categories) / sizeof(mime_categories[0]); i++) {
            const int cat_len = strlen(mime_categories[i]);
            if (!strncmp(mime_categories[i], ctype, cat_len)) {
                const char* mime_ext = ctype + cat_len;
                if (*mime_ext == '/') {
                    mime_ext++;
                    // remove possible 'x-' and 'vnd.' prefixes:
                    if (!strncmp("x-", mime_ext, 2)) {
                        mime_ext += 2;
                    }
                    if (!strncmp("vnd.", mime_ext, 4)) {
                        mime_ext += 4;
                    }

                    // strip off ';charset=...' bits and such-like:
					strncpy(new_ext, mime_ext, sizeof(new_ext));
					new_ext[sizeof(new_ext) - 1] = 0;

                    mime_ext = new_ext;
                    char* m_end = strchr(mime_ext, ';');
                    if (m_end) {
                        while (m_end > mime_ext) {
                            if (isspace(m_end[-1])) {
                                m_end--;
                                continue;
                            }
                            *m_end = 0;
                            break;
                        }
                    }

                    char* m_last = strrchr(mime_ext, '-');
                    if (m_last) {
                        mime_ext = m_last + 1;
                    }
                    m_end = strchr(mime_ext, '.');
                    if (m_end) {
                        m_end[0] = 0;
                    }
                    size_t cp_len = strlen(mime_ext);
                    if (cp_len > sizeof(new_ext) - 1) {
                        // 'extension' too long: forget it!
                        new_ext[0] = 0;
                        break;
                    }
					if (mime_ext != new_ext) {
						memmove(new_ext, mime_ext, strlen(mime_ext) + 1);
					}
                    break;
                }
            }
        }
    
        // sanitize new_ext: we are only interested in derived extensions containing letters and numbers:
        // e.g. 'html, 'mp3', ...
        for (const char* p = new_ext; *p; p++) {
            if (*p >= '0' && *p <= '9')
                continue;
            if (*p >= 'a' && *p <= 'z')
                continue;
            if (*p >= 'A' && *p <= 'Z')
                continue;
            // bad character encountered: nuke the entire extension!
            new_ext[0] = 0;
            break;
        }

        strlwr(new_ext);    // lowercase extension for convenience

        // do we have a non-empty filename extension?
        if (new_ext[0]) {
            return strdup(new_ext);
        }
    }

    return NULL;
}

/* sanitize a local file for writing, return TRUE on success */
bool tool_sanitize_output_file_path(struct per_transfer *per)
{
  struct GlobalConfig *global;
  struct OperationConfig *config;
  char* fname = per->outfile;
  char* aname = NULL;

  DEBUGASSERT(per);
  config = per->config;
  DEBUGASSERT(config);

  CURL* curl = per->curl;
  DEBUGASSERT(curl);

  global = config->global;

  const char* outdir = config->output_dir;
  int outdir_len = (outdir ? strlen(outdir) : 0);
  int starts_with_outdir = (outdir && strncmp(outdir, fname, outdir_len) == 0 && strchr("\\/", fname[outdir_len]));

  if (starts_with_outdir) {
      fname += outdir_len + 1; // skip path separator as well
  }

  const char *__hidden_prefix = "";
   
  if (config->sanitize_with_extreme_prejudice) {
      // config->failwithbody ?
      
      __hidden_prefix = "___";

      // - if filename is empty (or itself a directory), then we create a filename after the fact.
      // - if the filename is 'hidden' (i.e. starts with a '.'), the filename is *unhiddden.
      // - if the filename does not have an extension, an extension will be added, based on the mimetype
      //   reported by the server response. As this bit can be adversarial as well, we keep our
      //   sanity about it by restricting the length of the extension.

      // unescape possibly url-escaped filename for our convenience:
      {
          size_t len = strlen(fname);
          char* fn2 = NULL;
          if (CURLE_OK != Curl_urldecode(fname, len, &fn2, &len, SANITIZE_CTRL)) {
              errorf(global, "failure during filename sanitization: out of memory?\n");
              return FALSE;
          }

          if (CURL_SANITIZE_ERR_OK != curl_sanitize_file_name(&fname, fn2, CURL_SANITIZE_ALLOW_ONLY_RELATIVE_PATH)) {
              errorf(global, "failure during filename sanitization: out of memory?\n");
              return FALSE;
          }
      }
  }
  else {   // !config->sanitize_with_extreme_prejudice

      // prep for free(fname) + free(per->outfile) afterwards: prevent double free when we travel this branch.
      //per->outfile = NULL;
      
      // - if the filename does not have an extension, an extension will be added, based on the mimetype
      //   reported by the server response. As this bit can be adversarial as well, we keep our
      //   sanity about it by restricting the length of the extension.
  }

  const char* fn = find_beyond_all(fname, "\\/:");
  int fn_offset = (int)(fn - fname);

  bool empty = !*fn;
  bool hidden = (*fn == '.');

  // We would like to derive a 'sane' filename extension from the server-reported mime-type
  // when our current filename has NO extension.
  // We ALSO benefit from doing this when the actual filename has a 'nonsense extension',
  // which can happen due to the filename having been derived off the request URL, where
  // you might get something like:
  //     https://dl.acm.org/doi/abs/10.1145/3532342.3532351
  // and you would thus end up with thee 'nonsense filename':
  //     3532342.3532351
  // where appending a 'sane' mime-type based extension MIGHT help.
  //
  // However, we MUST defer fixing that until we have the MIME-type info from the
  // server's response headers or similar server-side info, which is info we currently
  // do NOT YET have. Until that time, we live with the fact that this here file don't have
  // a preferred file extension yet. ;-)

  aname = aprintf("%s%s%.*s%s%s", (starts_with_outdir ? outdir : ""), (starts_with_outdir ? "/" : ""),
                  fn_offset, fname, (hidden ? __hidden_prefix : ""), (empty ? "__download__" : fn));
  if (!aname) {
      errorf(global, "out of memory\n");
      if (fname != per->outfile)
        free(fname);
      return FALSE;
  }
  if (fname != per->outfile)
      free(fname);
  free(per->outfile);
  per->outfile = aname;
      
  if(!aname || !*aname) {
    warnf(global, "Remote filename has no length");
    return FALSE;
  }

  return TRUE;
}


/*
 * Return an allocated new path with file extension affixed (or not, if it wasn't deemed necessary). Return NULL on error.
 *
 * Do note that the file path given has already been sanitized, so no need for that again!
 */
static char *tool_affix_most_suitable_filename_extension(const char *fname, struct per_transfer *per)
{
  struct GlobalConfig *global;
  struct OperationConfig *config;
  char* aname = NULL;

  DEBUGASSERT(per);
  config = per->config;
  DEBUGASSERT(config);

  CURL* curl = per->curl;
  DEBUGASSERT(curl);

  global = config->global;

  const char *__unknown__ext = NULL;
   
  if (config->sanitize_with_extreme_prejudice) {
      // config->failwithbody ?
      
      __unknown__ext = "unknown";
  }

  const char* fn = find_beyond_all(fname, "\\/:");

  bool hidden = (*fn == '.');
  const char* ext = strrchr(fn + hidden, '.');

  int fn_length = (ext ? (ext - fname) : INT_MAX);

  // We would like to derive a 'sane' filename extension from the server-reported mime-type
  // when our current filename has NO extension.
  // We ALSO benefit from doing this when the actual filename has a 'nonsense extension',
  // which can happen due to the filename having been derived off the request URL, where
  // you might get something like:
  //     https://dl.acm.org/doi/abs/10.1145/3532342.3532351
  // and you would thus end up with thee 'nonsense filename':
  //     3532342.3532351
  // where appending a 'sane' mime-type based extension MIGHT help:

  if (ext) {
    ext++;    // skip dot

    // sanitize ext: we are only interested in derived extensions containing letters and numbers:
    // e.g. 'html, 'mp3', ...
    for (const char* p = ext; *p; p++) {
      if (*p >= '0' && *p <= '9')
        continue;
      if (*p >= 'a' && *p <= 'z')
        continue;
      if (*p >= 'A' && *p <= 'Z')
        continue;
      // bad character encountered: nuke the entire extension!
      ext = NULL;
      break;
    }
    if (!ext[0])
      ext = NULL;
  }

  char *new_ext = get_file_extension_for_response_content_type(fn, per);

  // when the server gave us a sensible extension through MIME-type info or otherwise, that one prevails over
  // the current ëxtension"the filename may or may not have:
  if (!ext || !new_ext) {
    // when we could not determine a proper & *sane* filename extension from the mimetype, we simply resolve to '.unknown' / *empty*, depending on configuration.
    if (!new_ext) {
        ext = __unknown__ext;
    }
    else {
        ext = new_ext;
    }

    if (!ext)
        ext = "";
            
    fn_length = INT_MAX;
  }
  else {
    // we already have an extension for the filename, but the mime-type derived one might be 'saner'.
    // There are now 3 scenarios to consider:
    // 1. both extensions are the same (case-*IN*sensitive comparison, because '.PDF' == '.pdf' for our purposes!)
    // 2. the filename extension is 'sane', the mime-derived one isn't so much: keep the filename ext as-is.
    // 3. the filename extension is less 'sane' than the mime-derived one. Append the mime-ext, i.e.
    //    treat the filename extension as part of the filename instead.
    //    e.g. filename="3532342.3532351" --> ext="3532351", mimee-ext="html" --> new filename="3532342.3532351.html"

    if (curl_strequal(new_ext, ext)) {
        ext = new_ext;
    }
    else {
        static const char* preferred_extensions[] = {
            "html",
            "js",
            "css",
            NULL
        };
        bool mime_ext_is_preferred = FALSE;
        for (const char** pe = preferred_extensions; *pe && !mime_ext_is_preferred; pe++) {
            mime_ext_is_preferred = (0 == strcmp(*pe, new_ext));
        }
        DEBUGASSERT(*ext);
        if ( ! (
                mime_ext_is_preferred ||
                (strlen(ext) >= strlen(new_ext))
        )) {
            // 2. no-op, ergo: keep extension as-is

			free(new_ext);
			ext = new_ext = strdup(ext);
			if (!new_ext) {
				errorf(global, "out of memory\n");
				return NULL;
			}
			strlwr((char *)ext);    // lowercase extension for convenience
        }
        else {
            // 3. drop file ext; use mime ext.
            fn_length = INT_MAX;
            ext = new_ext;
        }
    }
  }

  // also fix 
  aname = aprintf("%.*s%s%s", fn_length, fname, (*ext ? "." : ""), ext);
  if (!aname) {
      errorf(global, "out of memory\n");
      free(new_ext);
      return NULL;
  }
  free(new_ext);
      
  return aname;
}


/* create/open a local file for writing, return TRUE on success */
bool tool_create_output_file(struct OutStruct *outs,
                             struct per_transfer *per)
{
  struct GlobalConfig *global;
  struct OperationConfig *config;
  FILE *file = NULL;
  file_clobber_mode_t clobber_mode;
  int duplicate = 1;
  const char *fname = outs->filename;

  if (!fname || !*fname) {
      fname = per->outfile;
  }

  DEBUGASSERT(outs);
  DEBUGASSERT(per);
  config = per->config;
  DEBUGASSERT(config);

  CURL* curl = per->curl;
  DEBUGASSERT(curl);

  global = config->global;

  clobber_mode = config->file_clobber_mode;

  if (config->sanitize_with_extreme_prejudice) {
      // never clobber generated download filenames:
      clobber_mode = CLOBBER_NEVER;
  }

  DEBUGASSERT(fname && *fname);

  // NOW is the time to check server response headers for MIME info, etc.
  // to help affix a most proper filename extension:
  fname = tool_affix_most_suitable_filename_extension(fname, per);
  if (!fname) {
    return FALSE;
  }

  if (outs->is_cd_filename && clobber_mode != CLOBBER_ALWAYS) {
    /* default behaviour: don't overwrite existing files */
    clobber_mode = CLOBBER_NEVER;
  }
  else {
    /* default behaviour: open file for writing (overwrite!) *UNLESS* --noclobber is set */
  }

  if (config->create_dirs) {
      CURLcode result = create_dir_hierarchy(fname, global);
      /* create_dir_hierarchy shows error upon CURLE_WRITE_ERROR */
      if (result) {
          warnf(global, "Failed to create the path directories to file %s: %s", fname,
              strerror(errno));
          free((void *)fname);
          return FALSE;
      }
  }

  if (clobber_mode != CLOBBER_NEVER) {
    /* open file for writing */
    file = fopen(fname, "wb");
  }
  else {
    int fd;
    int fn_ext_pos = 0;
    const char* fn = find_beyond_all(fname, "\\/:");
    bool hidden = (*fn == '.');
    char* fn_ext = strrchr(fn + hidden, '.');

    if (!fn_ext) {
        /* filename has no extension */
        fn_ext_pos = strlen(fname);
    }
    else {
        fn_ext_pos = fn_ext - fname;
    }
    
    fn_ext = strdup(fname + fn_ext_pos);
    if (!fn_ext) {
        errorf(global, "out of memory");
        free((void*)fname);
        return FALSE;
    }

    do {
      fd = open(fname, O_CREAT | O_WRONLY | O_EXCL | CURL_O_BINARY, OPENMODE);
      /* Keep retrying in the hope that it is not interrupted sometime */
    } while(fd == -1 && errno == EINTR);
    if (fd == -1) {
      int next_num = 1;
      size_t len = strlen(fname);
      size_t newlen = len + 13; /* nul + 1-11 digits + dot */
      char* newname = NULL;

      /* Guard against wraparound in new filename */
      if(newlen < len) {
        errorf(global, "overflow in filename generation");
        free(fn_ext);
        free((void*)fname);
        return FALSE;
      }

      bool has_risky_filename = hidden;

      while(fd == -1 && /* have not successfully opened a file */
            (errno == EEXIST || errno == EISDIR) &&
            /* because we keep having files that already exist */
            next_num < 100 /* and we have not reached the retry limit */ ) {
        free(newname);
        newname = aprintf("%.*s%s.%02d%s", fn_ext_pos, fname, (has_risky_filename ? "__hidden__" : ""), next_num, fn_ext);
        if (!newname) {
            errorf(global, "out of memory");
            free(fn_ext);
            free((void*)fname);
            return FALSE;
        }
        next_num++;
        do {
          fd = open(newname, O_CREAT | O_WRONLY | O_EXCL | CURL_O_BINARY,
                             OPENMODE);
          /* Keep retrying in the hope that it is not interrupted sometime */
        } while(fd == -1 && errno == EINTR);
      }

      free((void*)fname);
      fname = newname;
    }

    Curl_safefree(fn_ext);

    /* An else statement to not overwrite existing files and not retry with
       new numbered names (which would cover
       config->file_clobber_mode == CLOBBER_DEFAULT && outs->is_cd_filename)
       is not needed because we would have failed earlier, in the while loop
       and `fd` would now be -1 */
    if(fd != -1) {
      file = fdopen(fd, "wb");
      if(!file)
        close(fd);
    }
  }

  if(!file) {
    warnf(global, "Failed to open the file %s: %s", outs->filename,
          strerror(errno));
    free((void*)fname);
    return FALSE;
  }

  if (outs->alloc_filename)
    free(outs->filename);
  if (fname == per->outfile) 
    per->outfile = NULL;
  outs->filename = (char *)fname;
  outs->alloc_filename = TRUE;

  if (fname != per->outfile) {
      free(per->outfile);
      per->outfile = strdup(fname);
      if (!per->outfile) {
          errorf(global, "out of memory\n");
          fclose(file);
          return FALSE;
      }
  }

  Curl_infof(per->curl, "Data will be written to output file: %s", per->outfile);

  outs->s_isreg = TRUE;
  outs->fopened = TRUE;
  outs->stream = file;
  outs->bytes = 0;
  outs->init = 0;
  return TRUE;
}

/*
** callback for CURLOPT_WRITEFUNCTION
*/

size_t tool_write_cb(char *buffer, size_t sz, size_t nmemb, void *userdata)
{
  size_t rc;
  struct per_transfer *per = userdata;
  struct OutStruct *outs = &per->outs;
  struct OperationConfig *config = per->config;
  size_t bytes = sz * nmemb;
  bool is_tty = config->global->isatty;
#ifdef _WIN32
  CONSOLE_SCREEN_BUFFER_INFO console_info;
  intptr_t fhnd;
#endif

#ifdef DEBUGBUILD
  {
    char *tty = curl_getenv("CURL_ISATTY");
    if(tty) {
      is_tty = TRUE;
      curl_free(tty);
    }
  }

  if(config->show_headers) {
    if(bytes > (size_t)CURL_MAX_HTTP_HEADER) {
      warnf(config->global, "Header data size exceeds single call write "
            "limit");
      return CURL_WRITEFUNC_ERROR;
    }
  }
  else {
    if(bytes > (size_t)CURL_MAX_WRITE_SIZE) {
      warnf(config->global, "Data size exceeds single call write limit");
      return CURL_WRITEFUNC_ERROR;
    }
  }

  {
    /* Some internal congruency checks on received OutStruct */
    bool check_fails = FALSE;
    if(outs->filename) {
      /* regular file */
      if(!*outs->filename)
        check_fails = TRUE;
      if(!outs->s_isreg)
        check_fails = TRUE;
      if(outs->fopened && !outs->stream)
        check_fails = TRUE;
      if(!outs->fopened && outs->stream)
        check_fails = TRUE;
      if(!outs->fopened && outs->bytes)
        check_fails = TRUE;
    }
    else {
      /* standard stream */
      if(!outs->stream || outs->s_isreg || outs->fopened)
        check_fails = TRUE;
      if(outs->alloc_filename || outs->is_cd_filename || outs->init)
        check_fails = TRUE;
    }
    if(check_fails) {
      warnf(config->global, "Invalid output struct data for write callback");
      return CURL_WRITEFUNC_ERROR;
    }
  }
#endif

  if(!outs->stream && !tool_create_output_file(outs, per))
    return CURL_WRITEFUNC_ERROR;

  if(is_tty && (outs->bytes < 2000) && !config->terminal_binary_ok) {
    /* binary output to terminal? */
    if(memchr(buffer, 0, bytes)) {
      warnf(config->global, "Binary output can mess up your terminal. "
            "Use \"--output -\" to tell curl to output it to your terminal "
            "anyway, or consider \"--output <FILE>\" to save to a file.");

      if (config->output_dir) {
          warnf(config->global, "\n");
          warnf(config->global, "By the way: you specified --output-dir "
              "but output is still written to stdout as you apperently did not "
              "specify an --output or --remote-name-all option. Might be you "
              "wanted to do that?");
      }
      config->synthetic_error = TRUE;
      return CURL_WRITEFUNC_ERROR;
    }
  }

#ifdef _WIN32
  fhnd = _get_osfhandle(fileno(outs->stream));
  /* if Windows console then UTF-8 must be converted to UTF-16 */
  if(isatty(fileno(outs->stream)) &&
     GetConsoleScreenBufferInfo((HANDLE)fhnd, &console_info)) {
    wchar_t *wc_buf;
    DWORD wc_len, chars_written;
    unsigned char *rbuf = (unsigned char *)buffer;
    DWORD rlen = (DWORD)bytes;

#define IS_TRAILING_BYTE(x) (0x80 <= (x) && (x) < 0xC0)

    /* attempt to complete an incomplete UTF-8 sequence from previous call.
       the sequence does not have to be well-formed. */
    if(outs->utf8seq[0] && rlen) {
      bool complete = false;
      /* two byte sequence (lead byte 110yyyyy) */
      if(0xC0 <= outs->utf8seq[0] && outs->utf8seq[0] < 0xE0) {
        outs->utf8seq[1] = *rbuf++;
        --rlen;
        complete = true;
      }
      /* three byte sequence (lead byte 1110zzzz) */
      else if(0xE0 <= outs->utf8seq[0] && outs->utf8seq[0] < 0xF0) {
        if(!outs->utf8seq[1]) {
          outs->utf8seq[1] = *rbuf++;
          --rlen;
        }
        if(rlen && !outs->utf8seq[2]) {
          outs->utf8seq[2] = *rbuf++;
          --rlen;
          complete = true;
        }
      }
      /* four byte sequence (lead byte 11110uuu) */
      else if(0xF0 <= outs->utf8seq[0] && outs->utf8seq[0] < 0xF8) {
        if(!outs->utf8seq[1]) {
          outs->utf8seq[1] = *rbuf++;
          --rlen;
        }
        if(rlen && !outs->utf8seq[2]) {
          outs->utf8seq[2] = *rbuf++;
          --rlen;
        }
        if(rlen && !outs->utf8seq[3]) {
          outs->utf8seq[3] = *rbuf++;
          --rlen;
          complete = true;
        }
      }

      if(complete) {
        WCHAR prefix[3] = {0};  /* UTF-16 (1-2 WCHARs) + NUL */

        if(MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)outs->utf8seq, -1,
                               prefix, sizeof(prefix)/sizeof(prefix[0]))) {
          DEBUGASSERT(prefix[2] == L'\0');
          if(!WriteConsoleW(
              (HANDLE) fhnd,
              prefix,
              prefix[1] ? 2 : 1,
              &chars_written,
              NULL)) {
            return CURL_WRITEFUNC_ERROR;
          }
        }
        /* else: UTF-8 input was not well formed and OS is pre-Vista which
           drops invalid characters instead of writing U+FFFD to output.  */

        memset(outs->utf8seq, 0, sizeof(outs->utf8seq));
      }
    }

    /* suppress an incomplete utf-8 sequence at end of rbuf */
    if(!outs->utf8seq[0] && rlen && (rbuf[rlen - 1] & 0x80)) {
      /* check for lead byte from a two, three or four byte sequence */
      if(0xC0 <= rbuf[rlen - 1] && rbuf[rlen - 1] < 0xF8) {
        outs->utf8seq[0] = rbuf[rlen - 1];
        rlen -= 1;
      }
      else if(rlen >= 2 && IS_TRAILING_BYTE(rbuf[rlen - 1])) {
        /* check for lead byte from a three or four byte sequence */
        if(0xE0 <= rbuf[rlen - 2] && rbuf[rlen - 2] < 0xF8) {
          outs->utf8seq[0] = rbuf[rlen - 2];
          outs->utf8seq[1] = rbuf[rlen - 1];
          rlen -= 2;
        }
        else if(rlen >= 3 && IS_TRAILING_BYTE(rbuf[rlen - 2])) {
          /* check for lead byte from a four byte sequence */
          if(0xF0 <= rbuf[rlen - 3] && rbuf[rlen - 3] < 0xF8) {
            outs->utf8seq[0] = rbuf[rlen - 3];
            outs->utf8seq[1] = rbuf[rlen - 2];
            outs->utf8seq[2] = rbuf[rlen - 1];
            rlen -= 3;
          }
        }
      }
    }

    if(rlen) {
      /* calculate buffer size for wide characters */
      wc_len = (DWORD)MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)rbuf, (int)rlen,
                                          NULL, 0);
      if(!wc_len)
        return CURL_WRITEFUNC_ERROR;

      wc_buf = (wchar_t*) malloc(wc_len * sizeof(wchar_t));
      if(!wc_buf)
        return CURL_WRITEFUNC_ERROR;

      wc_len = (DWORD)MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)rbuf, (int)rlen,
                                          wc_buf, (int)wc_len);
      if(!wc_len) {
        free(wc_buf);
        return CURL_WRITEFUNC_ERROR;
      }

      if(!WriteConsoleW(
          (HANDLE) fhnd,
          wc_buf,
          wc_len,
          &chars_written,
          NULL)) {
        free(wc_buf);
        return CURL_WRITEFUNC_ERROR;
      }
      free(wc_buf);
    }

    rc = bytes;
  }
  else
#endif
  {
    if(per->hdrcbdata.headlist) {
      if(tool_write_headers(&per->hdrcbdata, outs->stream))
        return CURL_WRITEFUNC_ERROR;
    }
    rc = fwrite(buffer, sz, nmemb, outs->stream);
  }

  if(bytes == rc)
    /* we added this amount of data to the output */
    outs->bytes += bytes;

  if(config->readbusy) {
    config->readbusy = FALSE;
    curl_easy_pause(per->curl, CURLPAUSE_CONT);
  }

  if(config->nobuffer) {
    /* output buffering disabled */
    int res = fflush(outs->stream);
    if(res)
      return CURL_WRITEFUNC_ERROR;
  }

  return rc;
}
