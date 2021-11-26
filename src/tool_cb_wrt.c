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

/* create a local file for writing, return TRUE on success */
bool tool_create_output_file(struct OutStruct *outs,
                             struct per_transfer *per)
{
  struct GlobalConfig *global;
  struct OperationConfig *config;
  FILE *file = NULL;
  bool noclobber;
  bool overwrite;
  int duplicate = 1;
  char* name;
  char* aname = NULL;
  size_t fn_ext_pos = 0;
  char* fn_ext = NULL;

  DEBUGASSERT(outs);
  DEBUGASSERT(per);
  config = per->config;
  DEBUGASSERT(config);

  global = config->global;
  if(!outs->filename || !*outs->filename) {
    warnf(global, "Remote filename has no length!\n");
    return FALSE;
  }

  name = outs->filename;
  noclobber = config->noclobber_output_file;

  if(outs->is_cd_filename) {
    /* default behaviour: don't overwrite existing files */
    if(config->output_dir) {
      aname = aprintf("%s/%s", config->output_dir, name);
      if(!aname) {
        errorf(global, "out of memory\n");
        return FALSE;
      }
      name = aname;
    }
	overwrite = FALSE;
  }
  else {
	/* default behaviour: open file for writing (overwrite!) *UNLESS* --noclobber is set */
	overwrite = !noclobber;
  }

  if (noclobber) {
	  const char *p = strrchr(name, '.');
	  if (!p || strchr(p, '/')) {
		  /* filename has no extension */
		  fn_ext_pos = strlen(name);
	  }
	  else {
		  fn_ext_pos = p - name;
	  }
	  fn_ext = strdup(name + fn_ext_pos);
  }

  for (;;) {
	  if (!overwrite) {
		  /* do not overwrite existing file */
		  int fd = open(name, O_CREAT | O_WRONLY | O_EXCL | O_BINARY, OPENMODE);
		  if (fd != -1) {
			  file = fdopen(fd, "wb");
			  if (!file)
				  close(fd);
			  break;
		  }

		  if (!noclobber)
			  break;

		  /* check if we can open the file at all, i.e. if it actually exists. If not, we've got an invalid destination path.
		  
		     Of course, this will arrive at a possibly incorrect conclusion in the **fringe case** where *only* the existing file is inaccessible-for-reading due to strict user access limitations, but then one should not download new data while pointing at such a specifically protected file anyway.
           */
		  fd = open(name, O_RDONLY | O_BINARY, OPENMODE);
		  if (fd == -1) {
			  break;
		  }
		  close(fd);

		  /* when we get here, we've got a collision with an existing file and want to use a unique output name for our file */
		  {
			  char* newname = aprintf("%.*s-%04d%s", (int)fn_ext_pos, name, duplicate, fn_ext);
			  duplicate++;
			  free(aname);
			  aname = NULL;
			  if (outs->alloc_filename) {
				free(outs->filename);
			  }
			  free(per->outfile);
			  outs->alloc_filename = TRUE;
			  /* aname = */ name = outs->filename = newname;
			  per->outfile = strdup(newname);
		  }
	  }
	  else {
		  file = fopen(name, "wb");
		  break;
	  }
  }
  free(fn_ext);

  if(!file) {
    warnf(global, "Failed to create the file %s: %s\n", outs->filename,
          strerror(errno));
	free(aname);
	return FALSE;
  }

  free(aname);

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

  /*
   * Once that libcurl has called back tool_write_cb() the returned value
   * is checked against the amount that was intended to be written, if
   * it does not match then it fails with CURLE_WRITE_ERROR. So at this
   * point returning a value different from sz*nmemb indicates failure.
   */
  const size_t failure = bytes ? 0 : 1;

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
            "limit!\n");
      return failure;
    }
  }
  else {
    if(bytes > (size_t)CURL_MAX_WRITE_SIZE) {
      warnf(config->global, "Data size exceeds single call write limit!\n");
      return failure;
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
      warnf(config->global, "Invalid output struct data for write callback\n");
      return failure;
    }
  }
#endif

  if(!outs->stream && !tool_create_output_file(outs, per))
    return failure;

  if(is_tty && (outs->bytes < 2000) && !config->terminal_binary_ok) {
    /* binary output to terminal? */
    if(memchr(buffer, 0, bytes)) {
      warnf(config->global, "Binary output can mess up your terminal. "
            "Use \"--output -\" to tell curl to output it to your terminal "
            "anyway, or consider \"--output <FILE>\" to save to a file.\n");
      config->synthetic_error = ERR_BINARY_TERMINAL;
      return failure;
    }
  }

#ifdef WIN32
  fhnd = _get_osfhandle(fileno(outs->stream));
  if(isatty(fileno(outs->stream)) &&
     GetConsoleScreenBufferInfo((HANDLE)fhnd, &console_info)) {
    DWORD in_len = (DWORD)(sz * nmemb);
    wchar_t* wc_buf;
    DWORD wc_len;

    /* calculate buffer size for wide characters */
    wc_len = MultiByteToWideChar(CP_UTF8, 0, buffer, in_len,  NULL, 0);
    wc_buf = (wchar_t*) malloc(wc_len * sizeof(wchar_t));
    if(!wc_buf)
      return failure;

    /* calculate buffer size for multi-byte characters */
    wc_len = MultiByteToWideChar(CP_UTF8, 0, buffer, in_len, wc_buf, wc_len);
    if(!wc_len) {
      free(wc_buf);
      return failure;
    }

    if(!WriteConsoleW(
        (HANDLE) fhnd,
        wc_buf,
        wc_len,
        &wc_len,
        NULL)) {
      free(wc_buf);
      return failure;
    }
    free(wc_buf);
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
      return failure;
  }

  return rc;
}
