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

#include "timeval.h"

#if (defined(WIN32) || defined(WIN64)) && !defined(MSDOS)

#include "curl_setup.h"
#include <curl/curl.h>
#include "system_win32.h"
#include "version_win32.h"

#include <profileapi.h>
#include <sysinfoapi.h>

/* set in win32_init() */
//extern LARGE_INTEGER Curl_freq;
//extern bool Curl_isVistaOrGreater;

static LARGE_INTEGER Curl_freq;
static bool Curl_isVistaOrGreater;
static bool timer_initialized = FALSE;

/* In case of bug fix this function has a counterpart in tool_util.c */
struct curltime Curl_now(void)
{
  struct curltime now;

  if (!timer_initialized)
  {
	  if (curlx_verify_windows_version(6, 0, 0, PLATFORM_WINNT,
		  VERSION_GREATER_THAN_EQUAL))
	  {
		  Curl_isVistaOrGreater = TRUE;
		  QueryPerformanceFrequency(&Curl_freq);
	  }
	  else
	  {
		  Curl_isVistaOrGreater = FALSE;
	  }
	  timer_initialized = TRUE;
  }

  if (Curl_isVistaOrGreater) { /* QPC timer might have issues pre-Vista */
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);

    now.tv_sec = (time_t)(count.QuadPart / Curl_freq.QuadPart);
    now.tv_usec = (int)((count.QuadPart % Curl_freq.QuadPart) * 1000000 /
                        Curl_freq.QuadPart);
  }
  else {
#ifndef _WINRT

#define DELTA_EPOCH_IN_MICROSECS 11644473600000000Ui64

	FILETIME ft;
	unsigned __int64 tmpres = 0;

	GetSystemTimeAsFileTime(&ft);

	tmpres |= ft.dwHighDateTime;
	tmpres <<= 32;
	tmpres |= ft.dwLowDateTime;

	tmpres /= 10; /*convert into microseconds*/
	/*converting file time to unix epoch*/
	tmpres -= DELTA_EPOCH_IN_MICROSECS;
	now.tv_sec = (long)(tmpres / 1000000UL);
	now.tv_usec = (long)(tmpres % 1000000UL);

#elif (_WIN32_WINNT >= 0x0600)

    ULONGLONG milliseconds = GetTickCount64();

    now.tv_sec = milliseconds / 1000;
    now.tv_usec = (milliseconds % 1000) * 1000;

#else

	  /* Disable /analyze warning that GetTickCount64 is preferred  */
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:28159)
#endif
	  DWORD milliseconds = GetTickCount();
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

	  now.tv_sec = milliseconds / 1000;
	  now.tv_usec = (milliseconds % 1000) * 1000;

#endif
  }
  return now;
}

#elif defined(HAVE_CLOCK_GETTIME_MONOTONIC)

#include <sys/time.h>
#include <time.h>

struct curltime Curl_now(void)
{
  /*
  ** clock_gettime() is granted to be increased monotonically when the
  ** monotonic clock is queried. Time starting point is unspecified, it
  ** could be the system start-up time, the Epoch, or something else,
  ** in any case the time starting point does not change once that the
  ** system has started up.
  */
#ifdef HAVE_GETTIMEOFDAY
  struct timeval now;
#endif
  struct curltime cnow;
  struct timespec tsnow;

  /*
  ** clock_gettime() may be defined by Apple's SDK as weak symbol thus
  ** code compiles but fails during run-time if clock_gettime() is
  ** called on unsupported OS version.
  */
#if defined(__APPLE__) && defined(HAVE_BUILTIN_AVAILABLE) && \
        (HAVE_BUILTIN_AVAILABLE == 1)
  bool have_clock_gettime = FALSE;
  if(__builtin_available(macOS 10.12, iOS 10, tvOS 10, watchOS 3, *))
    have_clock_gettime = TRUE;
#endif

  if(
#if defined(__APPLE__) && defined(HAVE_BUILTIN_AVAILABLE) && \
        (HAVE_BUILTIN_AVAILABLE == 1)
    have_clock_gettime &&
#endif
    (0 == clock_gettime(CLOCK_MONOTONIC, &tsnow))) {
    cnow.tv_sec = tsnow.tv_sec;
    cnow.tv_usec = (unsigned int)(tsnow.tv_nsec / 1000);
  }
  /*
  ** Even when the configure process has truly detected monotonic clock
  ** availability, it might happen that it is not actually available at
  ** run-time. When this occurs simply fallback to other time source.
  */
#ifdef HAVE_GETTIMEOFDAY
  else {
    (void)gettimeofday(&now, NULL);
    cnow.tv_sec = now.tv_sec;
    cnow.tv_usec = (unsigned int)now.tv_usec;
  }
#else
  else {
    cnow.tv_sec = time(NULL);
    cnow.tv_usec = 0;
  }
#endif
  return cnow;
}

#elif defined(HAVE_MACH_ABSOLUTE_TIME)

#include <stdint.h>
#include <mach/mach_time.h>

struct curltime Curl_now(void)
{
  /*
  ** Monotonic timer on Mac OS is provided by mach_absolute_time(), which
  ** returns time in Mach "absolute time units," which are platform-dependent.
  ** To convert to nanoseconds, one must use conversion factors specified by
  ** mach_timebase_info().
  */
  static mach_timebase_info_data_t timebase;
  struct curltime cnow;
  uint64_t usecs;

  if(0 == timebase.denom)
    (void) mach_timebase_info(&timebase);

  usecs = mach_absolute_time();
  usecs *= timebase.numer;
  usecs /= timebase.denom;
  usecs /= 1000;

  cnow.tv_sec = usecs / 1000000;
  cnow.tv_usec = (int)(usecs % 1000000);

  return cnow;
}

#elif defined(HAVE_GETTIMEOFDAY)

#include <sys/time.h>
#include <time.h>

struct curltime Curl_now(void)
{
  /*
  ** gettimeofday() is not granted to be increased monotonically, due to
  ** clock drifting and external source time synchronization it can jump
  ** forward or backward in time.
  */
  struct timeval now;
  struct curltime ret;
  (void)gettimeofday(&now, NULL);
  ret.tv_sec = now.tv_sec;
  ret.tv_usec = (int)now.tv_usec;
  return ret;
}

#else

#include <time.h>

struct curltime Curl_now(void)
{
  /*
  ** time() returns the value of time in seconds since the Epoch.
  */
  struct curltime now;
  now.tv_sec = time(NULL);
  now.tv_usec = 0;
  return now;
}

#endif

/*
 * Returns: time difference in number of milliseconds. For too large diffs it
 * returns max value.
 *
 * @unittest: 1323
 */
timediff_t Curl_timediff(struct curltime newer, struct curltime older)
{
  timediff_t diff = (timediff_t)newer.tv_sec-older.tv_sec;
  if(diff >= (TIMEDIFF_T_MAX/1000))
    return TIMEDIFF_T_MAX;
  else if(diff <= (TIMEDIFF_T_MIN/1000))
    return TIMEDIFF_T_MIN;
  return diff * 1000 + (newer.tv_usec-older.tv_usec)/1000;
}

/*
 * Returns: time difference in number of microseconds. For too large diffs it
 * returns max value.
 */
timediff_t Curl_timediff_us(struct curltime newer, struct curltime older)
{
  timediff_t diff = (timediff_t)newer.tv_sec-older.tv_sec;
  if(diff >= (TIMEDIFF_T_MAX/1000000))
    return TIMEDIFF_T_MAX;
  else if(diff <= (TIMEDIFF_T_MIN/1000000))
    return TIMEDIFF_T_MIN;
  return diff * 1000000 + newer.tv_usec-older.tv_usec;
}


#if 0 // already defined in timediff.c

/*
 * Converts number of milliseconds into a timeval structure.
 *
 * Return values:
 *    NULL IF tv is NULL or ms < 0 (eg. no timeout -> blocking select)
 *    tv with 0 in both fields IF ms == 0 (eg. 0ms timeout -> polling select)
 *    tv with converted fields IF ms > 0 (eg. >0ms timeout -> waiting select)
 */
struct timeval *curlx_mstotv(struct timeval *tv, timediff_t ms)
{
  if(!tv)
    return NULL;

  if(ms < 0)
    return NULL;

  if(ms > 0) {
    timediff_t tv_sec = ms / 1000;
    timediff_t tv_usec = (ms % 1000) * 1000; /* max=999999 */
#ifdef HAVE_SUSECONDS_T
#if TIMEDIFF_T_MAX > TIME_T_MAX
    /* tv_sec overflow check in case time_t is signed */
    if(tv_sec > TIME_T_MAX)
      tv_sec = TIME_T_MAX;
#endif
    tv->tv_sec = (time_t)tv_sec;
    tv->tv_usec = (suseconds_t)tv_usec;
#elif defined(WIN32) || defined(WIN64) || defined(_WIN32) || defined(_WIN64) /* maybe also others in the future */
#if TIMEDIFF_T_MAX > LONG_MAX
    /* tv_sec overflow check on Windows there we know it is long */
    if(tv_sec > LONG_MAX)
      tv_sec = LONG_MAX;
#endif
    tv->tv_sec = (long)tv_sec;
    tv->tv_usec = (long)tv_usec;
#else
#if TIMEDIFF_T_MAX > INT_MAX
    /* tv_sec overflow check in case time_t is signed */
    if(tv_sec > INT_MAX)
      tv_sec = INT_MAX;
#endif
    tv->tv_sec = (int)tv_sec;
    tv->tv_usec = (int)tv_usec;
#endif
  }
  else {
    tv->tv_sec = 0;
    tv->tv_usec = 0;
  }

  return tv;
}

#endif
