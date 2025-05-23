#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc

# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_srcdir)/include is for libcurl's external include files
# $(top_builddir)/lib is for libcurl's generated lib/curl_config.h file
# $(top_srcdir)/lib for libcurl's lib/curl_setup.h and other "borrowed" files

AM_CPPFLAGS = -I$(top_srcdir)/include        \
              -I$(top_builddir)/lib          \
              -I$(top_srcdir)/lib            \
              -I$(top_srcdir)/src

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)

if DOING_NATIVE_WINDOWS
AM_CPPFLAGS += -DCURL_STATICLIB
endif
AM_CPPFLAGS += -DCURL_NO_GETADDRINFO_OVERRIDE

# Makefile.inc provides neat definitions
include Makefile.inc

EXTRA_DIST = base64.pl CMakeLists.txt .checksrc

CHECKSRC = $(CS_$(V))
CS_0 = @echo "  RUN     " $@;
CS_1 =
CS_ = $(CS_0)

checksrc:
	$(CHECKSRC)@PERL@ $(top_srcdir)/scripts/checksrc.pl $(srcdir)/*.[ch]

if DEBUGBUILD
# for debug builds, we scan the sources on all regular make invokes
all-local: checksrc
endif
