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

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
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

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifdef WIN32
#define OPENMODE S_IREAD | S_IWRITE
#else
#define OPENMODE S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
#endif

static char* find_beyond_all(char* s, const char* set)
{
	while (*set) {
		char* p = strrchr(s, *set);
		if (p)
			s = p + 1;
		set++;
	}
	return s;
}

// Produce a filename extension based on the mimetype
// reported by the server response. As this bit can be adversarial as well, we keep our
// sanity about it by restricting the length of the extension.
static char *get_file_extension_for_response_content_type(char* fname, struct per_transfer *per) {
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

		char new_ext[6] = "";

		// TODO: map known mime types, e.g. text/javascript, to extension, without using the heuristic code below.

		for (int i = 0; i < sizeof(mime_categories) / sizeof(mime_categories[0]); i++) {
			const int cat_len = strlen(mime_categories[i]);
			if (!strncmp(mime_categories[i], ctype, cat_len)) {
				char* mime_ext = ctype + cat_len;
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
					char* mime_str = strdup(mime_ext);

					mime_ext = mime_str;
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
						free(mime_str);
						break;
					}
					strncpy(new_ext, mime_ext, sizeof(new_ext));
					free(mime_str);
					break;
				}
			}
		}
	
		new_ext[sizeof(new_ext) - 1] = 0;

		// sanitize new_ext: we are only interested in derived extensions containing letters and numbeers:
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

/* create/open a local file for writing, return TRUE on success */
bool tool_create_output_file(struct OutStruct *outs,
                             struct per_transfer *per)
{
  struct GlobalConfig *global;
  struct OperationConfig *config;
  FILE *file = NULL;
  file_clobber_mode_t clobber_mode;
  int duplicate = 1;
  char* fname = outs->filename;
  char* aname = NULL;

  DEBUGASSERT(outs);
  DEBUGASSERT(per);
  config = per->config;
  DEBUGASSERT(config);

  CURL* curl = per->curl;
  DEBUGASSERT(curl);

  global = config->global;

  clobber_mode = config->file_clobber_mode;

  if (config->sanitize_with_extreme_prejudice) {
	  // config->failwithbody ?

	  /* if HTTP response >= 400, return error */
	  long code = 0;
	  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

	  // - if filename is empty (or itself a directory), then we create a filename after the fact.
	  // - if the filename is 'hidden' (i.e. starts with a '.'), the filename is *unhiddden.
	  // - if the filename does not have an extension, an extension will be added, based on the mimetype
	  //   reported by the server response. As this bit can be adversarial as well, we keep our
	  //   sanity about it by restricting the length of the extension.
	  char* fn = find_beyond_all(fname, "\\/:");
	  int fn_offset = (int)(fn - fname);

	  // unescape possibly url-escaped filename for our convenience:
	  {
		  size_t len = strlen(fn);
		  char* fn2 = NULL;
		  if (CURLE_OK != Curl_urldecode(fn, len, &fn2, &len, SANITIZE_CTRL)) {
			  errorf(global, "failure during filename sanitization: out of memory?\n");
			  return FALSE;
		  }

		  if (CURL_SANITIZE_ERR_OK != curl_sanitize_file_name(&fn, fn2, 0)) {
			  errorf(global, "failure during filename sanitization: out of memory?\n");
			  return FALSE;
		  }
	  }

	  bool empty = !*fn;
	  bool hidden = (*fn == '.');
	  char* ext = strrchr(fn + hidden, '.');

	  int fn_length = (ext ? (ext - fn) : INT_MAX);

	  // We would like to derive a 'sane' filename extension from the server-reported mime-type
	  // when our current filename has NO extension.
	  // We ALSO benefit from doing this when the actual filename has a 'nonsense extension',
	  // which can happen due to the filename having been derived off the request URL, where
	  // you might get something like:
	  //     https://dl.acm.org/doi/abs/10.1145/3532342.3532351
	  // and you would thus end up with thee 'nonsense filename':
	  //     3532342.3532351
	  // where appending a 'sane' mime-type based extension MIGHT help:

	  if (!ext || !ext[1])
		  ext = NULL;
	  else
		  ext++;

	  char *new_ext = get_file_extension_for_response_content_type(fname, per);

		if (!ext || !new_ext) {
			// when we could not determine a proper & *sane* filename extension from the mimetype, we simply resolve to '.unknown'
			if (!new_ext) {
				ext = "unknown";
			}
			else {
				ext = new_ext;
			}
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
				bool mime_ext_is_preferred = (!strcmp("html", new_ext) || !strcmp("js", new_ext) || !strcmp("css", new_ext)); /* TODO: vet the set of known-good extensions */
				DEBUGASSERT(*ext);
				if ( ! (
					    mime_ext_is_preferred ||
						(strlen(ext) >= strlen(new_ext))
				)) {
					// 2. no-op
				}
				else {
					// 3. drop file ext; use mime ext.
				    fn_length = INT_MAX;
					ext = new_ext;
				}
			}
		}

	  aname = aprintf("%.*s%s%.*s.%s", fn_offset, fname, (hidden ? "___" : ""), fn_length, (empty ? "__download__" : fn), ext);
	  if (!aname) {
		  errorf(global, "out of memory\n");
		  free(new_ext);
		  free(fn);
		  return FALSE;
	  }
	  if (outs->alloc_filename)
		  free(outs->filename);
	  fname = outs->filename = aname;
	  outs->alloc_filename = TRUE;
	  aname = NULL;
	  free(new_ext);
	  free(fn);

	  // never clobber generated download filenames:
	  clobber_mode = CLOBBER_NEVER;
  }
  else {   // !config->sanitize_with_extreme_prejudice

	  /* if HTTP response >= 400, return error */
	  long code = 0;
	  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

	  // - if the filename does not have an extension, an extension will be added, based on the mimetype
	  //   reported by the server response. As this bit can be adversarial as well, we keep our
	  //   sanity about it by restricting the length of the extension.
	  char* fn = find_beyond_all(fname, "\\/:");
	  int fn_offset = (int)(fn - fname);

	  bool empty = !*fn;
	  bool hidden = (*fn == '.');
	  char* ext = strrchr(fn + hidden, '.');

	  int fn_length = (ext ? (ext - fn) : INT_MAX);

	  // We would like to derive a 'sane' filename extension from the server-reported mime-type
	  // when our current filename has NO extension.
	  // We ALSO benefit from doing this when the actual filename has a 'nonsense extension',
	  // which can happen due to the filename having been derived off the request URL, where
	  // you might get something like:
	  //     https://dl.acm.org/doi/abs/10.1145/3532342.3532351
	  // and you would thus end up with thee 'nonsense filename':
	  //     3532342.3532351
	  // where appending a 'sane' mime-type based extension MIGHT help:

	  if (!ext || !ext[1])
		  ext = NULL;
	  else
		  ext++;

	  char *new_ext = get_file_extension_for_response_content_type(fname, per);

		if (!ext || !new_ext || empty) {
			// when we could not determine a proper & *sane* filename extension from the mimetype, we don't change anything
			if (new_ext && !empty) {
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
				bool mime_ext_is_preferred = (!strcmp("html", new_ext) || !strcmp("js", new_ext) || !strcmp("css", new_ext)); /* TODO: vet the set of known-good extensions */
				DEBUGASSERT(*ext);
				if ( ! (
					    mime_ext_is_preferred ||
						(strlen(ext) >= strlen(new_ext))
				)) {
					// 2. no-op
				}
				else {
					// 3. drop file ext; use mime ext.
				    fn_length = INT_MAX;
					ext = new_ext;
				}
			}
		}

	  aname = aprintf("%.*s%.*s%s%s", fn_offset, fname, fn_length, fn, (*ext ? "." : ""), ext);
	  if (!aname) {
		  errorf(global, "out of memory\n");
		  free(new_ext);
		  return FALSE;
	  }
	  if (outs->alloc_filename)
		  free(outs->filename);
	  fname = outs->filename = aname;
	  outs->alloc_filename = TRUE;
	  aname = NULL;
	  free(new_ext);
  }

  if(!fname || !*fname) {
    warnf(global, "Remote filename has no length");
    return FALSE;
  }

  if(config->output_dir && outs->is_cd_filename) {
    /* default behaviour: don't overwrite existing files */
    aname = aprintf("%s/%s", config->output_dir, fname);
    if(!aname) {
      errorf(global, "out of memory");
      return FALSE;
    }

	if (outs->alloc_filename)
		free(outs->filename);
	fname = outs->filename = aname;
	outs->alloc_filename = TRUE;
	aname = NULL;

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
		  free(aname);
		  return FALSE;
	  }
  }

  if (clobber_mode != CLOBBER_NEVER) {
    /* open file for writing */
    file = fopen(fname, "wb");
  }
  else {
    int fd;
	size_t fn_ext_pos = 0;
	char* fn = find_beyond_all(fname, "\\/:");
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
		free(aname);
		return FALSE;
	}

	do {
      fd = open(fname, O_CREAT | O_WRONLY | O_EXCL | O_BINARY, OPENMODE);
      /* Keep retrying in the hope that it isn't interrupted sometime */
    } while(fd == -1 && errno == EINTR);
    if (fd == -1) {
      int next_num = 1;
      size_t len = strlen(fname);
      size_t newlen = len + 13; /* nul + 1-11 digits + dot */
	  char* newname = NULL;

	  /* Guard against wraparound in new filename */
      if(newlen < len) {
        errorf(global, "overflow in filename generation");
		free(aname);
		free(fn_ext);
		return FALSE;
      }

	  bool has_risky_filename = hidden;

      while(fd == -1 && /* haven't successfully opened a file */
            (errno == EEXIST || errno == EISDIR) &&
            /* because we keep having files that already exist */
            next_num < 100 /* and we haven't reached the retry limit */ ) {
		free(newname);
		newname = aprintf("%.*s%s.%02d%s", (int)fn_ext_pos, fname, (has_risky_filename ? "__download__" : ""), next_num, fn_ext);
		if (!newname) {
            errorf(global, "out of memory");
			free(aname);
			free(fn_ext);
			return FALSE;
		}
		next_num++;
        do {
          fd = open(newname, O_CREAT | O_WRONLY | O_EXCL | O_BINARY, OPENMODE);
          /* Keep retrying in the hope that it isn't interrupted sometime */
        } while(fd == -1 && errno == EINTR);
      }
	  if (outs->alloc_filename)
		  free(outs->filename);
	  Curl_safefree(aname);
	  fname = NULL;
	  outs->filename = newname; /* remember the new one */
      outs->alloc_filename = TRUE;
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
	free(aname);
	return FALSE;
  }

  free(aname);

  aname = per->outfile;
  per->outfile = strdup(outs->filename);
  free(aname);
  if (!per->outfile) {
	  errorf(global, "out of memory\n");
	  fclose(file);
	  return FALSE;
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
#ifdef WIN32
  CONSOLE_SCREEN_BUFFER_INFO console_info;
  intptr_t fhnd;
#endif

#ifdef DEBUGBUILD
  {
    char *tty = tool_getenv("CURL_ISATTY");
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

#ifdef WIN32
  fhnd = _get_osfhandle(fileno(outs->stream));
  /* if windows console then UTF-8 must be converted to UTF-16 */
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
      wc_len = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)rbuf, rlen, NULL, 0);
      if(!wc_len)
        return CURL_WRITEFUNC_ERROR;

      wc_buf = (wchar_t*) malloc(wc_len * sizeof(wchar_t));
      if(!wc_buf)
        return CURL_WRITEFUNC_ERROR;

      wc_len = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)rbuf, rlen, wc_buf,
                                   wc_len);
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
    rc = fwrite(buffer, sz, nmemb, outs->stream);

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
