c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-safe-auth
Help: Do not authenticate to proxy using a clear text password
See-also: proxy-anyauth safe-auth
Added: 7.85.0
Category: proxy auth
Example: --proxy-user name:secret --proxy-safe-auth -x http://proxy $URL
Multi: boolean
---
Do not use a proxy authentication mechanism that would transmit a clear text
password over a non-encrypted connection.

This option has precedence over other mechanism selection option.
