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

#ifdef HAVE_PWD_H
#  undef __NO_NET_API /* required for building for AmigaOS */
#  include <pwd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <curl/mprintf.h>

#include "tool_homedir.h"

#include "memdebug.h" /* keep this as LAST include */

/* return the home directory of the current user as an allocated string */

/*
 * The original logic found a home dir to use (by checking a range of
 * environment variables and last using getpwuid) and returned that for the
 * parent to use.
 *
 * With the XDG_CONFIG_HOME support (added much later than the other), this
 * variable is treated differently in order to not ruin existing installations
 * even if this environment variable is set. If this variable is set, and a
 * file name is set to check, then only if that file name exists in that
 * directory will it be returned as a "home directory".
 *
 * 1. use CURL_HOME if set
 * 2. use XDG_CONFIG_HOME if set and fname is present
 * 3. use HOME if set
 * 4. Non-windows: use getpwuid
 * 5. Windows: use APPDATA if set
 * 6. Windows: use "USERPROFILE\Application Data" is set
 *
 * funcptr_getenv is a function pointer to the getenv to use, either Unicode
 * UTF-8 encoding (tool_getenv_utf8) or the current locale encoding
 * (tool_getenv_local). The former is only available in Windows Unicode builds
 * since in those builds curl/libcurl uses UTF-8 for internal file paths
 * regardless of the current locale. However, even in that case some
 * dependencies may still expect file paths in the current locale.
 *
 * So, respectively, there are three function-like macros in the header that
 * call this function: homedir_utf8, homedir_local, and homedir which maps to
 * one of the first two.
 */

char *tool_homedir(const char *fname, char *(*funcptr_getenv)(const char *))
{
  char *home;

  home = funcptr_getenv("CURL_HOME");
  if(home)
    return home;

  if(fname) {
    home = funcptr_getenv("XDG_CONFIG_HOME");
    if(home) {
      char *c = curl_maprintf("%s" DIR_CHAR "%s", home, fname);
      if(c) {
        int fd = open(c, O_RDONLY);
        curl_free(c);
        if(fd >= 0) {
          close(fd);
          return home;
        }
      }
      free(home);
    }
  }

  home = funcptr_getenv("HOME");
  if(home)
    return home;

#if defined(HAVE_GETPWUID) && defined(HAVE_GETEUID)
 {
   struct passwd *pw = getpwuid(geteuid());

   if(pw) {
     home = pw->pw_dir;
     if(home && home[0])
       home = strdup(home);
     else
       home = NULL;
   }
 }
#endif /* PWD-stuff */
#ifdef WIN32
  home = funcptr_getenv("APPDATA");
  if(!home) {
    char *env = funcptr_getenv("USERPROFILE");
    if(env) {
      char *path = curl_maprintf("%s\\Application Data", env);
      if(path) {
        home = strdup(path);
        curl_free(path);
      }
      free(env);
    }
  }
#endif /* WIN32 */
  return home;
}
