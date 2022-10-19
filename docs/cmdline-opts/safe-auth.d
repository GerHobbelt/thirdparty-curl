c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: safe-auth
Help: Do not authenticate using a clear text password
See-also: proxy-safe-auth
Protocols: FTP HTTP IMAP LDAP POP3 SMTP
Added: 7.85.0
Category: auth
Example: --user name:secret --safe-auth http://example.com
Multi: boolean
---
Do not use an authentication mechanism that would transmit a clear text
password over a non-encrypted connection.

This option has precedence over other mechanism selection option.
