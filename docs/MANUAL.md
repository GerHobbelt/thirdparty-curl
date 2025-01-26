<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl tutorial

## Simple Usage

Get the main page from a web-server:

    curl https://www.example.com/

Get a README file from an FTP server:

    curl ftp://ftp.example.com/README

Get a webpage from a server using port 8000:

    curl http://www.example.com:8000/

Get a directory listing of an FTP site:

    curl ftp://ftp.example.com/

Get the all terms matching curl from a dictionary:

    curl dict://dict.example.com/m:curl

Get the definition of curl from a dictionary:

    curl dict://dict.example.com/d:curl

Fetch two documents at once:

    curl ftp://ftp.example.com/ http://www.example.com:8000/

Get a file off an FTPS server:

    curl ftps://files.are.example.com/secrets.txt

or use the more appropriate FTPS way to get the same file:

    curl --ssl-reqd ftp://files.are.example.com/secrets.txt

Get a file from an SSH server using SFTP:

    curl -u username sftp://example.com/etc/issue

Get a file from an SSH server using SCP using a private key (not
password-protected) to authenticate:

    curl -u username: --key ~/.ssh/id_rsa scp://example.com/~/file.txt

Get a file from an SSH server using SCP using a private key
(password-protected) to authenticate:

    curl -u username: --key ~/.ssh/id_rsa --pass private_key_password
    scp://example.com/~/file.txt

Get the main page from an IPv6 web server:

    curl "http://[2001:1890:1112:1::20]/"

Get a file from an SMB server:

    curl -u "domain\username:passwd" smb://server.example.com/share/file.txt

## Download to a File

Get a webpage and store in a local file with a specific name:

    curl -o thatpage.html http://www.example.com/

Get a webpage and store in a local file, make the local file get the name of
the remote document (if no filename part is specified in the URL, this fails):

    curl -O http://www.example.com/index.html

Fetch two files and store them with their remote names:

    curl -O www.haxx.se/index.html -O curl.se/download.html

## Using Passwords

### FTP

To ftp files using name and password, include them in the URL like:

    curl ftp://name:passwd@ftp.server.example:port/full/path/to/file

or specify them with the `-u` flag like

    curl -u name:passwd ftp://ftp.server.example:port/full/path/to/file

### FTPS

It is just like for FTP, but you may also want to specify and use SSL-specific
options for certificates etc.

Note that using `FTPS://` as prefix is the *implicit* way as described in the
standards while the recommended *explicit* way is done by using `FTP://` and
the `--ssl-reqd` option.

### SFTP / SCP

This is similar to FTP, but you can use the `--key` option to specify a
private key to use instead of a password. Note that the private key may itself
be protected by a password that is unrelated to the login password of the
remote system; this password is specified using the `--pass` option.
Typically, curl automatically extracts the public key from the private key
file, but in cases where curl does not have the proper library support, a
matching public key file must be specified using the `--pubkey` option.

### HTTP

Curl also supports user and password in HTTP URLs, thus you can pick a file
like:

    curl http://name:passwd@http.server.example/full/path/to/file

or specify user and password separately like in

    curl -u name:passwd http://http.server.example/full/path/to/file

HTTP offers many different methods of authentication and curl supports
several: Basic, Digest, NTLM and Negotiate (SPNEGO). Without telling which
method to use, curl defaults to Basic. You can also ask curl to pick the most
secure ones out of the ones that the server accepts for the given URL, by
using `--anyauth`.

**Note**! According to the URL specification, HTTP URLs can not contain a user
and password, so that style does not work when using curl via a proxy, even
though curl allows it at other times. When using a proxy, you _must_ use the
`-u` style for user and password.

### HTTPS

Probably most commonly used with private certificates, as explained below.

## Proxy

curl supports both HTTP and SOCKS proxy servers, with optional authentication.
It does not have special support for FTP proxy servers since there are no
standards for those, but it can still be made to work with many of them. You
can also use both HTTP and SOCKS proxies to transfer files to and from FTP
servers.

Get an ftp file using an HTTP proxy named my-proxy that uses port 888:

    curl -x my-proxy:888 ftp://ftp.example.com/README

Get a file from an HTTP server that requires user and password, using the
same proxy as above:

    curl -u user:passwd -x my-proxy:888 http://www.example.com/

Some proxies require special authentication. Specify by using -U as above:

    curl -U user:passwd -x my-proxy:888 http://www.example.com/

A comma-separated list of hosts and domains which do not use the proxy can be
specified as:

    curl --noproxy example.com -x my-proxy:888 http://www.example.com/

If the proxy is specified with `--proxy1.0` instead of `--proxy` or `-x`, then
curl uses HTTP/1.0 instead of HTTP/1.1 for any `CONNECT` attempts.

curl also supports SOCKS4 and SOCKS5 proxies with `--socks4` and `--socks5`.

See also the environment variables Curl supports that offer further proxy
control.

Most FTP proxy servers are set up to appear as a normal FTP server from the
client's perspective, with special commands to select the remote FTP server.
curl supports the `-u`, `-Q` and `--ftp-account` options that can be used to
set up transfers through many FTP proxies. For example, a file can be uploaded
to a remote FTP server using a Blue Coat FTP proxy with the options:

    curl -u "username@ftp.server.example Proxy-Username:Remote-Pass"
      --ftp-account Proxy-Password --upload-file local-file
      ftp://my-ftp.proxy.example:21/remote/upload/path/

See the manual for your FTP proxy to determine the form it expects to set up
transfers, and curl's `-v` option to see exactly what curl is sending.

## Piping

Get a key file and add it with `apt-key` (when on a system that uses `apt` for
package management):

    curl -L https://apt.example.org/llvm-snapshot.gpg.key | sudo apt-key add -

The '|' pipes the output to STDIN. `-` tells `apt-key` that the key file
should be read from STDIN.

## Ranges

HTTP 1.1 introduced byte-ranges. Using this, a client can request to get only
one or more sub-parts of a specified document. Curl supports this with the
`-r` flag.

Get the first 100 bytes of a document:

    curl -r 0-99 http://www.example.com/

Get the last 500 bytes of a document:

    curl -r -500 http://www.example.com/

Curl also supports simple ranges for FTP files as well. Then you can only
specify start and stop position.

Get the first 100 bytes of a document using FTP:

    curl -r 0-99 ftp://www.example.com/README

## Uploading

### FTP / FTPS / SFTP / SCP

Upload all data on stdin to a specified server:

    curl -T - ftp://ftp.example.com/myfile

Upload data from a specified file, login with user and password:

    curl -T uploadfile -u user:passwd ftp://ftp.example.com/myfile

Upload a local file to the remote site, and use the local filename at the
remote site too:

    curl -T uploadfile -u user:passwd ftp://ftp.example.com/

Upload a local file to get appended to the remote file:

    curl -T localfile -a ftp://ftp.example.com/remotefile

Curl also supports ftp upload through a proxy, but only if the proxy is
configured to allow that kind of tunneling. If it does, you can run curl in a
fashion similar to:

    curl --proxytunnel -x proxy:port -T localfile ftp.example.com

### SMB / SMBS

    curl -T file.txt -u "domain\username:passwd"
      smb://server.example.com/share/

### HTTP

Upload all data on stdin to a specified HTTP site:

    curl -T - http://www.example.com/myfile

Note that the HTTP server must have been configured to accept PUT before this
can be done successfully.

For other ways to do HTTP data upload, see the POST section below.

## Verbose / Debug

If curl fails where it is not supposed to, if the servers do not let you in,
if you cannot understand the responses: use the `-v` flag to get verbose
fetching. Curl outputs lots of info and what it sends and receives in order to
let the user see all client-server interaction (but it does not show you the
actual data).

    curl -v ftp://ftp.example.com/

To get even more details and information on what curl does, try using the
`--trace` or `--trace-ascii` options with a given filename to log to, like
this:

    curl --trace my-trace.txt www.haxx.se


## Detailed Information

Different protocols provide different ways of getting detailed information
about specific files/documents. To get curl to show detailed information about
a single file, you should use `-I`/`--head` option. It displays all available
info on a single file for HTTP and FTP. The HTTP information is a lot more
extensive.

For HTTP, you can get the header information (the same as `-I` would show)
shown before the data by using `-i`/`--include`. Curl understands the
`-D`/`--dump-header` option when getting files from both FTP and HTTP, and it
then stores the headers in the specified file.

Store the HTTP headers in a separate file (headers.txt in the example):

      curl --dump-header headers.txt curl.se

Note that headers stored in a separate file can be useful at a later time if
you want curl to use cookies sent by the server. More about that in the
cookies section.

## POST (HTTP)

It is easy to post data using curl. This is done using the `-d <data>` option.
The post data must be urlencoded.

Post a simple `name` and `phone` guestbook.

    curl -d "name=Rafael%20Sagula&phone=3320780" http://www.example.com/guest.cgi

Or automatically [URL encode the data](https://everything.curl.dev/http/post/url-encode).

    curl --data-urlencode "name=Rafael Sagula&phone=3320780"
      http://www.example.com/guest.cgi

How to post a form with curl, lesson #1:

Dig out all the `<input>` tags in the form that you want to fill in.

If there is a normal post, you use `-d` to post. `-d` takes a full post
string, which is in the format

    <variable1>=<data1>&<variable2>=<data2>&...

The variable names are the names set with `"name="` in the `<input>` tags, and
the data is the contents you want to fill in for the inputs. The data *must*
be properly URL encoded. That means you replace space with + and that you
replace weird letters with `%XX` where `XX` is the hexadecimal representation
of the letter's ASCII code.

Example:

(say if `http://example.com` had the following html)

```html
<form action="post.cgi" method="post">
  <input name=user size=10>
  <input name=pass type=password size=10>
  <input name=id type=hidden value="blablabla">
  <input name=ding value="submit">
</form>
```

We want to enter user `foobar` with password `12345`.

To post to this, you would enter a curl command line like:

    curl -d "user=foobar&pass=12345&id=blablabla&ding=submit"
      http://example.com/post.cgi

While `-d` uses the application/x-www-form-urlencoded mime-type, generally
understood by CGI's and similar, curl also supports the more capable
multipart/form-data type. This latter type supports things like file upload.

`-F` accepts parameters like `-F "name=contents"`. If you want the contents to
be read from a file, use `@filename` as contents. When specifying a file, you
can also specify the file content type by appending `;type=<mime type>` to the
filename. You can also post the contents of several files in one field.  For
example, the field name `coolfiles` is used to send three files, with
different content types using the following syntax:

    curl -F "coolfiles=@fil1.gif;type=image/gif,fil2.txt,fil3.html"
      http://www.example.com/postit.cgi

If the content-type is not specified, curl tries to guess from the file
extension (it only knows a few), or use the previously specified type (from an
earlier file if several files are specified in a list) or else it uses the
default type `application/octet-stream`.

Emulate a fill-in form with `-F`. Let's say you fill in three fields in a
form. One field is a filename which to post, one field is your name and one
field is a file description. We want to post the file we have written named
`cooltext.txt`. To let curl do the posting of this data instead of your
favorite browser, you have to read the HTML source of the form page and find
the names of the input fields. In our example, the input field names are
`file`, `yourname` and `filedescription`.

    curl -F "file=@cooltext.txt" -F "yourname=Daniel"
      -F "filedescription=Cool text file with cool text inside"
      http://www.example.com/postit.cgi

To send two files in one post you can do it in two ways:

Send multiple files in a single field with a single field name:

    curl -F "pictures=@dog.gif,cat.gif" $URL

Send two fields with two field names

    curl -F "docpicture=@dog.gif" -F "catpicture=@cat.gif" $URL

To send a field value literally without interpreting a leading `@` or `<`, or
an embedded `;type=`, use `--form-string` instead of `-F`. This is recommended
when the value is obtained from a user or some other unpredictable
source. Under these circumstances, using `-F` instead of `--form-string` could
allow a user to trick curl into uploading a file.

## Referrer

An HTTP request has the option to include information about which address
referred it to the actual page. curl allows you to specify the referrer to be
used on the command line. It is especially useful to fool or trick stupid
servers or CGI scripts that rely on that information being available or
contain certain data.

    curl -e www.example.org http://www.example.com/

## User Agent

An HTTP request has the option to include information about the browser that
generated the request. Curl allows it to be specified on the command line. It
is especially useful to fool or trick stupid servers or CGI scripts that only
accept certain browsers.

Example:

    curl -A 'Mozilla/3.0 (Win95; I)' http://www.bank.example.com/

Other common strings:

- `Mozilla/3.0 (Win95; I)` - Netscape Version 3 for Windows 95
- `Mozilla/3.04 (Win95; U)` - Netscape Version 3 for Windows 95
- `Mozilla/2.02 (OS/2; U)` - Netscape Version 2 for OS/2
- `Mozilla/4.04 [en] (X11; U; AIX 4.2; Nav)` - Netscape for AIX
- `Mozilla/4.05 [en] (X11; U; Linux 2.0.32 i586)` - Netscape for Linux

Note that Internet Explorer tries hard to be compatible in every way:

- `Mozilla/4.0 (compatible; MSIE 4.01; Windows 95)` - MSIE for W95

Mozilla is not the only possible User-Agent name:

- `Konqueror/1.0` - KDE File Manager desktop client
- `Lynx/2.7.1 libwww-FM/2.14` - Lynx command line browser

## Cookies

Cookies are generally used by web servers to keep state information at the
client's side. The server sets cookies by sending a response line in the
headers that looks like `Set-Cookie: <data>` where the data part then
typically contains a set of `NAME=VALUE` pairs (separated by semicolons `;`
like `NAME1=VALUE1; NAME2=VALUE2;`). The server can also specify for what path
the cookie should be used for (by specifying `path=value`), when the cookie
should expire (`expire=DATE`), for what domain to use it (`domain=NAME`) and
if it should be used on secure connections only (`secure`).

If you have received a page from a server that contains a header like:

```http
Set-Cookie: sessionid=boo123; path="/foo";
```

it means the server wants that first pair passed on when we get anything in a
path beginning with `/foo`.

Example, get a page that wants my name passed in a cookie:

    curl -b "name=Daniel" www.example.com

Curl also has the ability to use previously received cookies in following
sessions. If you get cookies from a server and store them in a file in a
manner similar to:

    curl --dump-header headers www.example.com

... you can then in a second connect to that (or another) site, use the
cookies from the `headers.txt` file like:

    curl -b headers.txt www.example.com

While saving headers to a file is a working way to store cookies, it is
however error-prone and not the preferred way to do this. Instead, make curl
save the incoming cookies using the well-known Netscape cookie format like
this:

    curl -c cookies.txt www.example.com

Note that by specifying `-b` you enable the cookie engine and with `-L` you
can make curl follow a `location:` (which often is used in combination with
cookies). If a site sends cookies and a location field, you can use a
non-existing file to trigger the cookie awareness like:

    curl -L -b empty.txt www.example.com

The file to read cookies from must be formatted using plain HTTP headers OR as
Netscape's cookie file. Curl determines what kind it is based on the file
contents. In the above command, curl parses the header and store the cookies
received from www.example.com. curl sends the stored cookies which match the
request to the server as it follows the location. The file `empty.txt` may be
a nonexistent file.

To read and write cookies from a Netscape cookie file, you can set both `-b`
and `-c` to use the same file:

    curl -b cookies.txt -c cookies.txt www.example.com

## Progress Meter

The progress meter exists to show a user that something actually is
happening. The different fields in the output have the following meaning:

    % Total    % Received % Xferd  Average Speed          Time             Curr.
                                   Dload  Upload Total    Current  Left    Speed
    0  151M    0 38608    0     0   9406      0  4:41:43  0:00:04  4:41:39  9287

From left-to-right:

 - `%`           - percentage completed of the whole transfer
 - `Total`       - total size of the whole expected transfer
 - `%`           - percentage completed of the download
 - `Received`    - currently downloaded amount of bytes
 - `%`           - percentage completed of the upload
 - `Xferd`       - currently uploaded amount of bytes
 - `Average Speed Dload` - the average transfer speed of the download
 - `Average Speed Upload` - the average transfer speed of the upload
 - `Time Total`  - expected time to complete the operation
 - `Time Current` - time passed since the invoke
 - `Time Left`   - expected time left to completion
 - `Curr.Speed`  - the average transfer speed the last 5 seconds (the first
                   5 seconds of a transfer is based on less time of course.)

The `-#` option displays a totally different progress bar that does not need
much explanation!

## Speed Limit

Curl allows the user to set the transfer speed conditions that must be met to
let the transfer keep going. By using the switch `-y` and `-Y` you can make
curl abort transfers if the transfer speed is below the specified lowest limit
for a specified time.

To have curl abort the download if the speed is slower than 3000 bytes per
second for 1 minute, run:

    curl -Y 3000 -y 60 www.far-away.example.com

This can be used in combination with the overall time limit, so that the above
operation must be completed in whole within 30 minutes:

    curl -m 1800 -Y 3000 -y 60 www.far-away.example.com

Forcing curl not to transfer data faster than a given rate is also possible,
which might be useful if you are using a limited bandwidth connection and you
do not want your transfer to use all of it (sometimes referred to as
*bandwidth throttle*).

Make curl transfer data no faster than 10 kilobytes per second:

    curl --limit-rate 10K www.far-away.example.com

or

    curl --limit-rate 10240 www.far-away.example.com

Or prevent curl from uploading data faster than 1 megabyte per second:

    curl -T upload --limit-rate 1M ftp://uploads.example.com

When using the `--limit-rate` option, the transfer rate is regulated on a
per-second basis, which causes the total transfer speed to become lower than
the given number. Sometimes of course substantially lower, if your transfer
stalls during periods.

## Config File

Curl automatically tries to read the `.curlrc` file (or `_curlrc` file on
Microsoft Windows systems) from the user's home directory on startup.

The config file could be made up with normal command line switches, but you
can also specify the long options without the dashes to make it more
readable. You can separate the options and the parameter with spaces, or with
`=` or `:`. Comments can be used within the file. If the first letter on a
line is a `#`-symbol the rest of the line is treated as a comment.

If you want the parameter to contain spaces, you must enclose the entire
parameter within double quotes (`"`). Within those quotes, you specify a quote
as `\"`.

NOTE: You must specify options and their arguments on the same line.

Example, set default time out and proxy in a config file:

    # We want a 30 minute timeout:
    -m 1800
    # ... and we use a proxy for all accesses:
    proxy = proxy.our.domain.com:8080

Whitespaces ARE significant at the end of lines, but all whitespace leading
up to the first characters of each line are ignored.

Prevent curl from reading the default file by using -q as the first command
line parameter, like:

    curl -q www.example.org

Force curl to get and display a local help page in case it is invoked without
URL by making a config file similar to:

    # default url to get
    url = "http://help.with.curl.example.com/curlhelp.html"

You can specify another config file to be read by using the `-K`/`--config`
flag. If you set config filename to `-` it reads the config from stdin, which
can be handy if you want to hide options from being visible in process tables
etc:

    echo "user = user:passwd" | curl -K - http://that.secret.example.com

## Extra Headers

When using curl in your own programs, you may end up needing to pass on your
own custom headers when getting a webpage. You can do this by using the `-H`
flag.

Example, send the header `X-you-and-me: yes` to the server when getting a
page:

    curl -H "X-you-and-me: yes" love.example.com

This can also be useful in case you want curl to send a different text in a
header than it normally does. The `-H` header you specify then replaces the
header curl would normally send. If you replace an internal header with an
empty one, you prevent that header from being sent. To prevent the `Host:`
header from being used:

    curl -H "Host:" server.example.com

## FTP and Path Names

Do note that when getting files with a `ftp://` URL, the given path is
relative to the directory you enter. To get the file `README` from your home
directory at your ftp site, do:

    curl ftp://user:passwd@my.example.com/README

If you want the README file from the root directory of that same site, you
need to specify the absolute filename:

    curl ftp://user:passwd@my.example.com//README

(I.e with an extra slash in front of the filename.)

## SFTP and SCP and Path Names

With sftp: and scp: URLs, the path name given is the absolute name on the
server. To access a file relative to the remote user's home directory, prefix
the file with `/~/` , such as:

    curl -u $USER sftp://home.example.com/~/.bashrc

## FTP and Firewalls

The FTP protocol requires one of the involved parties to open a second
connection as soon as data is about to get transferred. There are two ways to
do this.

The default way for curl is to issue the PASV command which causes the server
to open another port and await another connection performed by the
client. This is good if the client is behind a firewall that does not allow
incoming connections.

    curl ftp.example.com

If the server, for example, is behind a firewall that does not allow
connections on ports other than 21 (or if it just does not support the `PASV`
command), the other way to do it is to use the `PORT` command and instruct the
server to connect to the client on the given IP number and port (as parameters
to the PORT command).

The `-P` flag to curl supports a few different options. Your machine may have
several IP-addresses and/or network interfaces and curl allows you to select
which of them to use. Default address can also be used:

    curl -P - ftp.example.com

Download with `PORT` but use the IP address of our `le0` interface (this does
not work on Windows):

    curl -P le0 ftp.example.com

Download with `PORT` but use 192.168.0.10 as our IP address to use:

    curl -P 192.168.0.10 ftp.example.com

## Network Interface

Get a webpage from a server using a specified port for the interface:

    curl --interface eth0:1 http://www.example.com/

or

    curl --interface 192.168.1.10 http://www.example.com/

## HTTPS

Secure HTTP requires a TLS library to be installed and used when curl is
built. If that is done, curl is capable of retrieving and posting documents
using the HTTPS protocol.

Example:

    curl https://secure.example.com

curl is also capable of using client certificates to get/post files from sites
that require valid certificates. The only drawback is that the certificate
needs to be in PEM-format. PEM is a standard and open format to store
certificates with, but it is not used by the most commonly used browsers. If
you want curl to use the certificates you use with your favorite browser, you
may need to download/compile a converter that can convert your browser's
formatted certificates to PEM formatted ones.

Example on how to automatically retrieve a document using a certificate with a
personal password:

    curl -E /path/to/cert.pem:password https://secure.example.com/

If you neglect to specify the password on the command line, you are prompted
for the correct password before any data can be received.

Many older HTTPS servers have problems with specific SSL or TLS versions,
which newer versions of OpenSSL etc use, therefore it is sometimes useful to
specify what TLS version curl should use.:

    curl --tlv1.0 https://secure.example.com/

Otherwise, curl attempts to use a sensible TLS default version.

## Resuming File Transfers

To continue a file transfer where it was previously aborted, curl supports
resume on HTTP(S) downloads as well as FTP uploads and downloads.

Continue downloading a document:

    curl -C - -o file ftp://ftp.example.com/path/file

Continue uploading a document:

    curl -C - -T file ftp://ftp.example.com/path/file

Continue downloading a document from a web server

    curl -C - -o file http://www.example.com/

## Time Conditions

HTTP allows a client to specify a time condition for the document it requests.
It is `If-Modified-Since` or `If-Unmodified-Since`. curl allows you to specify
them with the `-z`/`--time-cond` flag.

For example, you can easily make a download that only gets performed if the
remote file is newer than a local copy. It would be made like:

    curl -z local.html http://remote.example.com/remote.html

Or you can download a file only if the local file is newer than the remote
one. Do this by prepending the date string with a `-`, as in:

    curl -z -local.html http://remote.example.com/remote.html

You can specify a plain text date as condition. Tell curl to only download the
file if it was updated since January 12, 2012:

    curl -z "Jan 12 2012" http://remote.example.com/remote.html

curl accepts a wide range of date formats. You always make the date check the
other way around by prepending it with a dash (`-`).

## DICT

For fun try

    curl dict://dict.org/m:curl
    curl dict://dict.org/d:heisenbug:jargon
    curl dict://dict.org/d:daniel:gcide

Aliases for `m` are `match` and `find`, and aliases for `d` are `define` and
`lookup`. For example,

    curl dict://dict.org/find:curl

Commands that break the URL description of the RFC (but not the DICT
protocol) are

    curl dict://dict.org/show:db
    curl dict://dict.org/show:strat

Authentication support is still missing

## LDAP

If you have installed the OpenLDAP library, curl can take advantage of it and
offer `ldap://` support. On Windows, curl uses WinLDAP from Platform SDK by
default.

Default protocol version used by curl is LDAP version 3. Version 2 is used as
a fallback mechanism in case version 3 fails to connect.

LDAP is a complex thing and writing an LDAP query is not an easy
task. Familiarize yourself with the exact syntax description elsewhere. One
such place might be: [RFC 2255, The LDAP URL
Format](https://curl.se/rfc/rfc2255.txt)

To show you an example, this is how to get all people from an LDAP server that
has a certain subdomain in their email address:

    curl -B "ldap://ldap.example.com/o=frontec??sub?mail=*sth.example.com"

You also can use authentication when accessing LDAP catalog:

    curl -u user:passwd "ldap://ldap.example.com/o=frontec??sub?mail=*"
    curl "ldap://user:passwd@ldap.example.com/o=frontec??sub?mail=*"

By default, if user and password are provided, OpenLDAP/WinLDAP uses basic
authentication. On Windows you can control this behavior by providing one of
`--basic`, `--ntlm` or `--digest` option in curl command line

    curl --ntlm "ldap://user:passwd@ldap.example.com/o=frontec??sub?mail=*"

On Windows, if no user/password specified, auto-negotiation mechanism is used
with current logon credentials (SSPI/SPNEGO).

## Environment Variables

Curl reads and understands the following environment variables:

    http_proxy, HTTPS_PROXY, FTP_PROXY

They should be set for protocol-specific proxies. General proxy should be set
with

    ALL_PROXY

A comma-separated list of hostnames that should not go through any proxy is
set in (only an asterisk, `*` matches all hosts)

    NO_PROXY

If the hostname matches one of these strings, or the host is within the domain
of one of these strings, transactions with that node is not done over the
proxy. When a domain is used, it needs to start with a period. A user can
specify that both www.example.com and foo.example.com should not use a proxy
by setting `NO_PROXY` to `.example.com`. By including the full name you can
exclude specific hostnames, so to make `www.example.com` not use a proxy but
still have `foo.example.com` do it, set `NO_PROXY` to `www.example.com`.

The usage of the `-x`/`--proxy` flag overrides the environment variables.

## Netrc

Unix introduced the `.netrc` concept a long time ago. It is a way for a user
to specify name and password for commonly visited FTP sites in a file so that
you do not have to type them in each time you visit those sites. You realize
this is a big security risk if someone else gets hold of your passwords,
therefore most Unix programs do not read this file unless it is only readable
by yourself (curl does not care though).

Curl supports `.netrc` files if told to (using the `-n`/`--netrc` and
`--netrc-optional` options). This is not restricted to just FTP, so curl can
use it for all protocols where authentication is used.

A simple `.netrc` file could look something like:

    machine curl.se login iamdaniel password mysecret

## Custom Output

To better allow script programmers to get to know about the progress of curl,
the `-w`/`--write-out` option was introduced. Using this, you can specify what
information from the previous transfer you want to extract.

To display the amount of bytes downloaded together with some text and an
ending newline:

    curl -w 'We downloaded %{size_download} bytes\n' www.example.com

## Kerberos FTP Transfer

Curl supports kerberos4 and kerberos5/GSSAPI for FTP transfers. You need the
kerberos package installed and used at curl build time for it to be available.

First, get the krb-ticket the normal way, like with the `kinit`/`kauth` tool.
Then use curl in way similar to:

    curl --krb private ftp://krb4site.example.com -u username:fakepwd

There is no use for a password on the `-u` switch, but a blank one makes curl
ask for one and you already entered the real password to `kinit`/`kauth`.

## TELNET

The curl telnet support is basic and easy to use. Curl passes all data passed
to it on stdin to the remote server. Connect to a remote telnet server using a
command line similar to:

    curl telnet://remote.example.com

Enter the data to pass to the server on stdin. The result is sent to stdout or
to the file you specify with `-o`.

You might want the `-N`/`--no-buffer` option to switch off the buffered output
for slow connections or similar.

Pass options to the telnet protocol negotiation, by using the `-t` option. To
tell the server we use a vt100 terminal, try something like:

    curl -tTTYPE=vt100 telnet://remote.example.com

Other interesting options for it `-t` include:

 - `XDISPLOC=<X display>` Sets the X display location.
 - `NEW_ENV=<var,val>` Sets an environment variable.

NOTE: The telnet protocol does not specify any way to login with a specified
user and password so curl cannot do that automatically. To do that, you need to
track when the login prompt is received and send the username and password
accordingly.

## Persistent Connections

Specifying multiple files on a single command line makes curl transfer all of
them, one after the other in the specified order.

libcurl attempts to use persistent connections for the transfers so that the
second transfer to the same host can use the same connection that was already
initiated and was left open in the previous transfer. This greatly decreases
connection time for all but the first transfer and it makes a far better use
of the network.

Note that curl cannot use persistent connections for transfers that are used
in subsequent curl invokes. Try to stuff as many URLs as possible on the same
command line if they are using the same host, as that makes the transfers
faster. If you use an HTTP proxy for file transfers, practically all transfers
are persistent.

## Multiple Transfers With A Single Command Line

As is mentioned above, you can download multiple files with one command line
by simply adding more URLs. If you want those to get saved to a local file
instead of just printed to stdout, you need to add one save option for each
URL you specify. Note that this also goes for the `-O` option (but not
`--remote-name-all`).

For example: get two files and use `-O` for the first and a custom file
name for the second:

    curl -O http://example.com/file.txt ftp://example.com/moo.exe -o moo.jpg

You can also upload multiple files in a similar fashion:

    curl -T local1 ftp://example.com/moo.exe -T local2 ftp://example.com/moo2.txt

## IPv6

curl connects to a server with IPv6 when a host lookup returns an IPv6 address
and fall back to IPv4 if the connection fails. The `--ipv4` and `--ipv6`
options can specify which address to use when both are available. IPv6
addresses can also be specified directly in URLs using the syntax:

    http://[2001:1890:1112:1::20]/overview.html

When this style is used, the `-g` option must be given to stop curl from
interpreting the square brackets as special globbing characters. Link local
and site local addresses including a scope identifier, such as `fe80::1234%1`,
may also be used, but the scope portion must be numeric or match an existing
network interface on Linux and the percent character must be URL escaped. The
previous example in an SFTP URL might look like:

    sftp://[fe80::1234%251]/

IPv6 addresses provided other than in URLs (e.g. to the `--proxy`,
`--interface` or `--ftp-port` options) should not be URL encoded.

## Mailing Lists

For your convenience, we have several open mailing lists to discuss curl, its
development and things relevant to this. Get all info at
https://curl.se/mail/.

Please direct curl questions, feature requests and trouble reports to one of
these mailing lists instead of mailing any individual.

Available lists include:

### `curl-users`

Users of the command line tool. How to use it, what does not work, new
features, related tools, questions, news, installations, compilations,
running, porting etc.

### `curl-library`

Developers using or developing libcurl. Bugs, extensions, improvements.

### `curl-announce`

Low-traffic. Only receives announcements of new public versions. At worst,
that makes something like one or two mails per month, but usually only one
mail every second month.

### `curl-and-php`

Using the curl functions in PHP. Everything curl with a PHP angle. Or PHP with
a curl angle.

### `curl-and-python`

Python hackers using curl with or without the python binding pycurl.



# curl(1) manpage

    curl [options / URLs]

## DESCRIPTION

`curl` is a tool for transferring data from or to a server using URLs. It
supports these protocols: DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS,
IMAP, IMAPS, LDAP, LDAPS, MQTT, POP3, POP3S, RTMP, RTMPS, RTSP, SCP, SFTP,
SMB, SMBS, SMTP, SMTPS, TELNET, TFTP, WS and WSS.

curl is powered by libcurl for all transfer-related features. See
`libcurl(3)` for details.


## URL

The URL syntax is protocol-dependent. You find a detailed description in
RFC 3986.

If you provide a URL without a leading `protocol://` scheme, curl guesses
what protocol you want. It then defaults to HTTP but assumes others based on
often-used host name prefixes. For example, for host names starting with
"ftp." `curl` assumes you want FTP.

You can specify any amount of URLs on the command line. They are fetched in a
sequential manner in the specified order unless you use `--parallel`. You can
specify command line options and URLs mixed and in any order on the command
line.

`curl` attempts to reuse connections when doing multiple transfers, so that
getting many files from the same server do not use multiple connects and setup
handshakes. This improves speed. Connection reuse can only be done for URLs
specified for a single command line invocation and cannot be performed between
separate curl runs.

Provide an IPv6 zone id in the URL with an escaped percentage sign. Like in

    http://[fe80::3%25eth0]/

Everything provided on the command line that is not a command line option or
its argument, `curl` assumes is a URL and treats it as such.


## GLOBBING

You can specify multiple URLs or parts of URLs by writing lists within braces
or ranges within brackets. We call this "globbing".

Provide a list with three different names like this:

    http://site.{one,two,three}.com

or you can get sequences of alphanumeric series by using `[]` as in:

    ftp://ftp.example.com/file[1-100].txt

    ftp://ftp.example.com/file[001-100].txt              (with leading zeros)

    ftp://ftp.example.com/file[a-z].txt

Nested sequences are not supported, but you can use several ones next to each
other:

    http://example.com/archive[1996-1999]/vol[1-4]/part{a,b,c}.html

You can specify a step counter for the ranges to get every Nth number or
letter:

    http://example.com/file[1-100:10].txt

    http://example.com/file[a-z:2].txt

When using `[]` or `{}` sequences when invoked from a command line prompt, you
probably have to put the full URL within double quotes to avoid the shell from
interfering with it. This also goes for other characters treated special, like
for example `&`, `?` and `*`.

Switch off globbing with `--globoff`.


## VARIABLES

`curl` supports command line variables (added in 8.3.0). Set variables with
`--variable name=content` or `--variable name@file` (where "file" can be stdin if
set to a single dash (`-`)).

Variable contents can expanded in option parameters using "{{name}}" (without
the quotes) if the option name is prefixed with "--expand-". This gets the
contents of the variable "name" inserted, or a blank if the name does not
exist as a variable. Insert "{{" verbatim in the string by prefixing it with a
backslash, like "\\{{".

You an access and expand environment variables by first importing them. You
can select to either require the environment variable to be set or you can
provide a default value in case it is not already set. Plain `--variable %name`
imports the variable called `name` but exits with an error if that environment
variable is not already set. To provide a default value if it is not set, use
`--variable %name=content` or `--variable %name@content`.

Example. Get the USER environment variable into the URL, fail if USER is not
set:

   --variable `%USER`
   --expand-url = "https://example.com/api/{{USER}}/method"

When expanding variables, `curl` supports a set of functions that can make the
variable contents more convenient to use. It can trim leading and trailing
white space with `trim`, it can output the contents as a JSON quoted string
with `json`, URL encode the string with `url` or base64 encode it with
`b64`. You apply function to a variable expansion, add them colon separated to
the right side of the variable. Variable content holding null bytes that are
not encoded when expanded cause error.

Example: get the contents of a file called `$HOME/.secret` into a variable
called "fix". Make sure that the content is trimmed and percent-encoded sent
as POST data:

    --variable %HOME
    --expand-variable fix@{{HOME}}/.secret
    --expand-data "{{fix:trim:url}}"
    https://example.com/

Command line variables and expansions were added in in 8.3.0.


## OUTPUT

If not told otherwise, `curl` writes the received data to stdout. It can be
instructed to instead save that data into a local file, using the `--output` or
`--remote-name` options. If `curl` is given multiple URLs to transfer on the
command line, it similarly needs multiple options for where to save them.

`curl` does not parse or otherwise "understand" the content it gets or writes as
output. It does no encoding or decoding, unless explicitly asked to with
dedicated command line options.


## PROTOCOLS

`curl` supports numerous protocols, or put in URL terms: schemes. Your
particular build may not support them all.

- `DICT`
    
  Lets you lookup words using online dictionaries.

- `FILE`

  Read or write local files. curl does not support accessing `file:// URL`
  remotely, but when running on Microsoft Windows using the native UNC approach
  works.
  
- `FTP(S)`

  `curl` supports the File Transfer Protocol with a lot of tweaks and levers. With
  or without using TLS.
  
- `GOPHER(S)`

  Retrieve files.

- `HTTP(S)`

  `curl` supports HTTP with numerous options and variations. It can speak HTTP
  version 0.9, 1.0, 1.1, 2 and 3 depending on build options and the correct
  command line options.

- `IMAP(S)`

  Using the mail reading protocol, curl can "download" emails for you. With or
  without using TLS.

- `LDAP(S)`

  curl can do directory lookups for you, with or without TLS.
  
- `MQTT`

  `curl` supports MQTT version 3. Downloading over MQTT equals "subscribe" to a
  topic while uploading/posting equals "publish" on a topic. MQTT over TLS is
  not supported (yet).

- `POP3(S)`

  Downloading from a pop3 server means getting a mail. With or without using
  TLS.
  
- `RTMP(S)`

  The "Realtime Messaging Protocol" is primarily used to serve streaming media
  and curl can download it.
  
- `RTSP`

  `curl` supports RTSP 1.0 downloads.
  
- `SCP`

  `curl` supports SSH version 2 scp transfers.
  
- `SFTP`

  `curl` supports SFTP (draft 5) done over SSH version 2.
  
- `SMB(S)`

  `curl` supports SMB version 1 for upload and download.
  
- `SMTP(S)`

  Uploading contents to an SMTP server means sending an email. With or without
  TLS.
  
- `TELNET`

  Telling `curl` to fetch a telnet URL starts an interactive session where it
  sends what it reads on stdin and outputs what the server sends it.
  
- `TFTP`

  `curl` can do TFTP downloads and uploads.
  
  
## "PROGRESS METER"

`curl` normally displays a progress meter during operations, indicating the
amount of transferred data, transfer speeds and estimated time left, etc. The
progress meter displays the transfer rate in bytes per second. The suffixes
(k, M, G, T, P) are 1024 based. For example 1k is 1024 bytes. 1M is 1048576
bytes.

`curl` displays this data to the terminal by default, so if you invoke curl to
do an operation and it is about to write data to the terminal, it
`disables` the progress meter as otherwise it would mess up the output
mixing progress meter and response data.

If you want a progress meter for HTTP POST or PUT requests, you need to
redirect the response output to a file, using shell redirect (`>`), `--output` or
similar.

This does not apply to FTP upload as that operation does not spit out any
response data to the terminal.

If you prefer a progress "bar" instead of the regular meter, `--progress-bar` is
your friend. You can also disable the progress meter completely with the
`--silent` option.


## VERSION

This man page describes curl 8.5.0. If you use a later version, chances are
this man page does not fully document it. If you use an earlier version, this
document tries to include version information about which specific version
that introduced changes.

You can always learn which the latest curl version is by running

    curl https://curl.se/info

The online version of this man page is always showing the latest incarnation:
https://curl.se/docs/manpage.html
    
    
## OPTIONS

Options start with one or two dashes. Many of the options require an
additional value next to them. If provided text does not start with a dash, it
is presumed to be and treated as a URL.

The short "single-dash" form of the options, -d for example, may be used with
or without a space between it and its value, although a space is a recommended
separator. The long "double-dash" form, --data for example, requires a space
between it and its value.

Short version options that do not need any additional values can be used
immediately next to each other, like for example you can specify all the
options `-O`, `-L` and `-v` at once as `-OLv`.

In general, all boolean options are enabled with --`option` and yet again
disabled with --`no-`option. That is, you use the same option name but
prefix it with "no-". However, in this list we mostly only list and show the
`--option` version of them.

When `--next` is used, it resets the parser state and you start again with a
clean option state, except for the options that are "global". Global options
retain their values and meaning even after `--next`.

The following options are global:





## FILES

- `~/.curlrc`

  Default config file, see --config for details.
  
  
## ENVIRONMENT

The environment variables can be specified in lower case or upper case. The
lower case version has precedence. http_proxy is an exception as it is only
available in lower case.

Using an environment variable to set the proxy has the same effect as using
the --proxy option.

- "http_proxy [protocol://]<host>[:port]"

  Sets the proxy server to use for HTTP.

- "HTTPS_PROXY [protocol://]<host>[:port]"

  Sets the proxy server to use for HTTPS.
  
- "[url-protocol]_PROXY [protocol://]<host>[:port]"

  Sets the proxy server to use for [url-protocol], where the protocol is a
  protocol that curl supports and as specified in a URL. FTP, FTPS, POP3, IMAP,
  SMTP, LDAP, etc.
  
- "ALL_PROXY [protocol://]<host>[:port]"

  Sets the proxy server to use if no protocol-specific proxy is set.

- "NO_PROXY <comma-separated list of hosts/domains>"

  list of host names that should not go through any proxy. If set to an asterisk
  `*` only, it matches all hosts. Each name in this list is matched as either
  a domain name which contains the hostname, or the hostname itself.

  This environment variable disables use of the proxy even when specified with
  the `--proxy` option. That is
  
       NO_PROXY=direct.example.com curl -x http://proxy.example.com
       http://direct.example.com
       
  accesses the target URL directly, and

       NO_PROXY=direct.example.com curl -x http://proxy.example.com
       http://somewhere.example.com
       
  accesses the target URL through the proxy.

  The list of host names can also be include numerical IP addresses, and IPv6
  versions should then be given without enclosing brackets.

  IP addresses can be specified using CIDR notation: an appended slash and
  number specifies the number of "network bits" out of the address to use in the
  comparison (added in 7.86.0). For example "192.168.0.0/16" would match all
  addresses starting with "192.168".

- "APPDATA <dir>"

  On Windows, this variable is used when trying to find the home directory. If
  the primary home variable are all unset.

- "COLUMNS <terminal width>"

  If set, the specified number of characters is used as the terminal width when
  the alternative progress-bar is shown. If not set, curl tries to figure it out
  using other ways.

- "CURL_CA_BUNDLE <file>"

  If set, it is used as the --cacert value.

- "CURL_HOME <dir>"

  If set, is the first variable curl checks when trying to find its home
  directory. If not set, it continues to check `XDG_CONFIG_HOME`

- "CURL_SSL_BACKEND <TLS backend>"

  If curl was built with support for "MultiSSL", meaning that it has built-in
  support for more than one TLS backend, this environment variable can be set to
  the case insensitive name of the particular backend to use when curl is
  invoked. Setting a name that is not a built-in alternative makes curl stay
  with the default.

  SSL backend names (case-insensitive): `bearssl`, `gnutls`, `mbedtls`,
  `openssl`, `rustls`, `schannel`, `secure-transport`, `wolfssl`

- "HOME <dir>"

  If set, this is used to find the home directory when that is needed. Like when
  looking for the default .curlrc. `CURL_HOME` and `XDG_CONFIG_HOME`
  have preference.

- "QLOGDIR <directory name>"

  If curl was built with HTTP/3 support, setting this environment variable to a
  local directory makes curl produce `qlogs` in that directory, using file
  names named after the destination connection id (in hex). Do note that these
  files can become rather large. Works with the ngtcp2 and quiche QUIC backends.

- SHELL

  Used on VMS when trying to detect if using a `DCL` or a `unix` shell.

- "SSL_CERT_DIR <dir>"

  If set, it is used as the --capath value.

- "SSL_CERT_FILE <path>"

  If set, it is used as the --cacert value.

- "SSLKEYLOGFILE <file name>"

  If you set this environment variable to a file name, curl stores TLS secrets
  from its connections in that file when invoked to enable you to analyze the
  TLS traffic in real time using network analyzing tools such as Wireshark. This
  works with the following TLS backends: OpenSSL, libressl, BoringSSL, GnuTLS
  and wolfSSL.

- "USERPROFILE <dir>"

  On Windows, this variable is used when trying to find the home directory. If
  the other, primary, variable are all unset. If set, curl uses the path
  ``"$USERPROFILE\\Application Data"``.

- "XDG_CONFIG_HOME <dir>"

  If `CURL_HOME` is not set, this variable is checked when looking for a
  default .curlrc file.



## PROXY PROTOCOL PREFIXES

The proxy string may be specified with a protocol:// prefix to specify
alternative proxy protocols.

If no protocol is specified in the proxy string or if the string does not
match a supported one, the proxy is treated as an HTTP proxy.

The supported proxy protocol prefixes are as follows:

- "http://"

  Makes it use it as an HTTP proxy. The default if no scheme prefix is used.

- "https://"

  Makes it treated as an `HTTPS` proxy.

- "socks4://"

  Makes it the equivalent of --socks4

- "socks4a://"

  Makes it the equivalent of --socks4a

- "socks5://"

  Makes it the equivalent of --socks5

- "socks5h://"

  Makes it the equivalent of --socks5-hostname



## EXIT CODES

There are a bunch of different error codes and their corresponding error
messages that may appear under error conditions. At the time of this writing,
the exit codes are:

- 0

  Success. The operation completed successfully according to the instructions.

- 1

  Unsupported protocol. This build of curl has no support for this protocol.

- 2

  Failed to initialize.

- 3

  URL malformed. The syntax was not correct.

- 4

  A feature or option that was needed to perform the desired request was not
  enabled or was explicitly disabled at build-time. To make curl able to do
  this, you probably need another build of libcurl.

- 5

  Could not resolve proxy. The given proxy host could not be resolved.

- 6

  Could not resolve host. The given remote host could not be resolved.

- 7

  Failed to connect to host.

- 8

  Weird server reply. The server sent data curl could not parse.

- 9

  FTP access denied. The server denied login or denied access to the particular
  resource or directory you wanted to reach. Most often you tried to change to a
  directory that does not exist on the server.

- 10

  FTP accept failed. While waiting for the server to connect back when an active
  FTP session is used, an error code was sent over the control connection or
  similar.

- 11

  FTP weird PASS reply. Curl could not parse the reply sent to the PASS request.

- 12

  During an active FTP session while waiting for the server to connect back to
  curl, the timeout expired.

- 13

  FTP weird PASV reply, Curl could not parse the reply sent to the PASV request.

- 14

  FTP weird 227 format. Curl could not parse the 227-line the server sent.

- 15

  FTP cannot use host. Could not resolve the host IP we got in the 227-line.

- 16

  HTTP/2 error. A problem was detected in the HTTP2 framing layer. This is
  somewhat generic and can be one out of several problems, see the error message
  for details.

- 17

  FTP could not set binary. Could not change transfer method to binary.

- 18

  Partial file. Only a part of the file was transferred.

- 19

  FTP could not download/access the given file, the RETR (or similar) command
  failed.

- 21

  FTP quote error. A quote command returned error from the server.

- 22

  HTTP page not retrieved. The requested URL was not found or returned another
  error with the HTTP error code being 400 or above. This return code only
  appears if --fail is used.

- 23

  Write error. Curl could not write data to a local filesystem or similar.

- 25

  Failed starting the upload. For FTP, the server typically denied the STOR
  command.

- 26

  Read error. Various reading problems.

- 27

  Out of memory. A memory allocation request failed.

- 28

  Operation timeout. The specified time-out period was reached according to the
  conditions.

- 30

  FTP PORT failed. The PORT command failed. Not all FTP servers support the PORT
  command, try doing a transfer using PASV instead!

- 31

  FTP could not use REST. The REST command failed. This command is used for
  resumed FTP transfers.

- 33

  HTTP range error. The range "command" did not work.

- 34

  HTTP post error. Internal post-request generation error.

- 35

  SSL connect error. The SSL handshaking failed.

- 36

  Bad download resume. Could not continue an earlier aborted download.

- 37

  FILE could not read file. Failed to open the file. Permissions?

- 38

  LDAP cannot bind. LDAP bind operation failed.

- 39

  LDAP search failed.

- 41

  Function not found. A required LDAP function was not found.

- 42

  Aborted by callback. An application told curl to abort the operation.

- 43

  Internal error. A function was called with a bad parameter.

- 45

  Interface error. A specified outgoing interface could not be used.

- 47

  Too many redirects. When following redirects, curl hit the maximum amount.

- 48

  Unknown option specified to libcurl. This indicates that you passed a weird
  option to curl that was passed on to libcurl and rejected. Read up in the
  manual!

- 49

  Malformed telnet option.

- 52

  The server did not reply anything, which here is considered an error.

- 53

  SSL crypto engine not found.

- 54

  Cannot set SSL crypto engine as default.

- 55

  Failed sending network data.

- 56

  Failure in receiving network data.

- 58

  Problem with the local certificate.

- 59

  Could not use specified SSL cipher.

- 60

  Peer certificate cannot be authenticated with known CA certificates.

- 61

  Unrecognized transfer encoding.

- 63

  Maximum file size exceeded.

- 64

  Requested FTP SSL level failed.

- 65

  Sending the data requires a rewind that failed.

- 66

  Failed to initialize SSL Engine.

- 67

  The user name, password, or similar was not accepted and curl failed to log in.

- 68

  File not found on TFTP server.

- 69

  Permission problem on TFTP server.

- 70

  Out of disk space on TFTP server.

- 71

  Illegal TFTP operation.

- 72

  Unknown TFTP transfer ID.

- 73

  File already exists (TFTP).

- 74

  No such user (TFTP).

- 77

  Problem reading the SSL CA cert (path? access rights?).

- 78

  The resource referenced in the URL does not exist.

- 79

  An unspecified error occurred during the SSH session.

- 80

  Failed to shut down the SSL connection.

- 82

  Could not load CRL file, missing or wrong format.

- 83

  Issuer check failed.

- 84

  The FTP PRET command failed.

- 85

  Mismatch of RTSP CSeq numbers.

- 86

  Mismatch of RTSP Session Identifiers.

- 87

  Unable to parse FTP file list.

- 88

  FTP chunk callback reported error.

- 89

  No connection available, the session is queued.

- 90

  SSL public key does not matched pinned public key.

- 91

  Invalid SSL certificate status.

- 92

  Stream error in HTTP/2 framing layer.

- 93

  An API function was called from inside a callback.

- 94

  An authentication function returned an error.

- 95

  A problem was detected in the HTTP/3 layer. This is somewhat generic and can
  be one out of several problems, see the error message for details.

- 96

  QUIC connection error. This error may be caused by an SSL library error. QUIC
  is the protocol used for HTTP/3 transfers.

- 97

  Proxy handshake error.

- 98

  A client-side certificate is required to complete the TLS handshake.

- 99

  Poll or select returned fatal error.

- XX

  More error codes might appear here in future releases. The existing ones are
  meant to never change.


## BUGS

If you experience any problems with curl, submit an issue in the project`s bug
tracker on GitHub: https://github.com/curl/curl/issues


## AUTHORS / CONTRIBUTORS

Daniel Stenberg is the main author, but the whole list of contributors is
found in the separate THANKS file.


## WWW

https://curl.se
