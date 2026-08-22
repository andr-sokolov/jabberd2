# jabberd2
Jabber Open Source Server (2.x)

[![Build Status](https://travis-ci.org/jabberd2/jabberd2.svg?branch=master)](https://travis-ci.org/jabberd2/jabberd2)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/8550/badge.svg)](https://scan.coverity.com/projects/jabberd)
[![Join the chat at Gitter](https://badges.gitter.im/jabberd2/jabberd2.svg)](https://gitter.im/jabberd2/jabberd2?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Flattr this](https://button.flattr.com/flattr-badge-large.png)](https://flattr.com/submit/auto?fid=8n22qr&url=https%3A%2F%2Fgithub.com%2Fjabberd2%2Fjabberd2)

Thanks for downloading jabberd2. Below are some basic instructions to
get you started. Complete documentation is available at http://jabberd2.org/

-- the jabberd team


## Required packages:

 - expat - XML parsing libraries
     http://expat.sourceforge.net/
 - GnuSASL (1.1 or higher) - Simple Authentication and Security Layer library
     http://www.gnu.org/software/gsasl/

### Optional packages:

 - GNU Libidn (0.3.0 or higher) - needed for JID canonicalisation
     http://www.gnu.org/software/libidn/
 - OpenSSL (0.9.6b or higher) - needed for SSL/TLS support
     http://www.openssl.org/news/
 - zlib (1.2.3 or higher) - needed for stream compression
     http://www.zlib.net/
 - http-parser
     http://github.com/nodejs/http-parser


## Build:

    % ./configure
    % make
    % make install

### Options to ./configure:

    % ./configure --help
    [...]


## Configure:

  Edit $prefix/etc/(router|sm|c2s).xml to taste. In
  particular, make sure you setup for your choice of data storage
  correctly. If you're using the Berkeley DB backend, you'll need to
  create /var/run/jabberd and sets its permissions so that the server
  processes can find it.
  
  If you're using a SQL backend, you'll need to create an account for
  the server to use, and create the tables. Load db-setup.mysql or
  db-setup.pgsql from the tools/ directory into your database to do
  this.

  If you plan to use the jabberd wrapper script, make sure you look at
  the paths in the $prefix/etc/jabber/jabberd.cfg.


## Run:

  You can either run all of the pieces separately:

    % $prefix/bin/router &
    % $prefix/bin/sm &
    % $prefix/bin/c2s &

  Or you can run them all from the jabberd wrapper script:

    % $prefix/jabberd &

  All the processes can take the following switches:

    -c use an alternate config file
    -D output lots of debugging info (if compiled with --enable-debug)


## Upgrade:

  Please see NEWS file.


## Support:

- Webpage: http://jabberd2.org/
- Mailinglist: jabberd2@lists.xiaoka.com
  (Subscribe by sending mail to jabberd2-subscribe@lists.xiaoka.com)

When requesting assistance, please note that the following things can
provide useful information which may assist with finding your problem:

 - debug logs (compile with --enable-debug and run with -D)
 - running components seperately (ie without the wrapper script)
 - config.log

Please try to provide as much relevant information as possible when
reporting problems - it will make helping you much easier.


## Copyright & License:
  
    jabberd - Jabber Open Source Server
    Copyright (c) 2002-2012 Jeremie Miller, Thomas Muldowney,
                            Ryan Eatmon, Robert Norris, Tomasz Sterna.
  
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
  
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
    GNU General Public License for more details.
  
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
  
    As a special exception, the authors give permission to link this
    program with the OpenSSL library and distribute the resulting binary.


 util/base64.c was originally taken from the
 Apache web server project.
   Originally copyright (c) 1995-2003 Apache Software Foundation.
 
 util/md5.c was taken from Ghostscript.
   Originally copyright (c) 1999-2002 Aladdin Enterprises.
 
 util/sha1.c was taken from Mozilla.
   Originally copyright (c) 1995-1999 Cryptography Research, Inc.
