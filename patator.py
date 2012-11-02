#!/usr/bin/env python

# Copyright (C) 2012 Sebastien MACKE
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2, as published by the
# Free Software Foundation
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details (http://www.gnu.org/licenses/gpl.txt).

__author__  = 'Sebastien Macke'
__email__   = 'patator@hsc.fr'
__url__     = 'http://www.hsc.fr/ressources/outils/patator/'
__git__     = 'http://code.google.com/p/patator/'
__version__ = '0.4'
__license__ = 'GPLv2'
__banner__  = 'Patator v%s (%s)' % (__version__, __git__)
 
# README {{{

'''
INTRODUCTION
------------

* What ?

Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.

Currently it supports the following modules:
  - ftp_login     : Brute-force FTP
  - ssh_login     : Brute-force SSH
  - telnet_login  : Brute-force Telnet
  - smtp_login    : Brute-force SMTP
  - smtp_vrfy     : Enumerate valid users using the SMTP 'VRFY' command
  - smtp_rcpt     : Enumerate valid users using the SMTP 'RCPT TO' command
  - finger_lookup : Enumerate valid users using Finger
  - http_fuzz     : Brute-force HTTP
  - pop_login     : Brute-force POP3
  - pop_passd     : Brute-force poppassd (http://netwinsite.com/poppassd/)
  - imap_login    : Brute-force IMAP4
  - ldap_login    : Brute-force LDAP
  - smb_login     : Brute-force SMB
  - smb_lookupsid : Brute-force SMB SID-lookup
  - vmauthd_login : Brute-force VMware Authentication Daemon
  - mssql_login   : Brute-force MSSQL
  - oracle_login  : Brute-force Oracle
  - mysql_login   : Brute-force MySQL
  - pgsql_login   : Brute-force PostgreSQL
  - vnc_login     : Brute-force VNC

  - dns_forward   : Brute-force DNS
  - dns_reverse   : Brute-force DNS (reverse lookup subnets)
  - snmp_login    : Brute-force SNMPv1/2 and SNMPv3

  - unzip_pass    : Brute-force the password of encrypted ZIP files
  - keystore_pass : Brute-force the password of Java keystore files

Future modules to be implemented:
  - rdp_login

The name "Patator" comes from http://www.youtube.com/watch?v=xoBkBvnTTjo
"Whatever the payload to fire, always use the same cannon"

* Why ?

Basically, I got tired of using Medusa, Hydra, Ncrack, Metasploit auxiliary modules, Nmap NSE scripts and the like because:
  - they either do not work or are not reliable (got me false negatives several times in the past)
  - they are not flexible enough (how to iterate over all wordlists, fuzz any module parameter)
  - they lack useful features (display progress or pause during execution)


FEATURES
--------
  * No false negatives, as it is the user that decides what results to ignore based on:
      + status code of response
      + size of response
      + matching string or regex in response data
      + ... see --help

  * Modular design
      + not limited to network modules (eg. the unzip_pass module)
      + not limited to brute-forcing (eg. remote exploit testing, or vulnerable version probing)

  * Interactive runtime
      + show verbose progress
      + pause/unpause execution
      + increase/decrease verbosity
      + add new actions & conditions during runtime (eg. to exclude more types of response from showing)
      + ... press h to see all available interactive commands

  * Use persistent connections (ie. will test several passwords until the server disconnects)

  * Multi-threaded

  * Flexible user input
    - Any module parameter can be fuzzed:
      + use FILE[0-9] keywords to iterate on a file
      + use COMBO[0-9] keywords to iterate on the combo entries of a file
      + use NET[0-9] keywords to iterate on every host of a network subnet

    - Iteration over the joined wordlists can be done in any order

  * Save every response (along with request) to seperate log files for later reviewing


INSTALL
-------

* Dependencies (best tested versions)

                 |  Required for  |                        URL                         | Version |
--------------------------------------------------------------------------------------------------
paramiko         | SSH            | http://www.lag.net/paramiko/                       | 1.7.7.1 |
--------------------------------------------------------------------------------------------------
pycurl           | HTTP           | http://pycurl.sourceforge.net/                     |  7.19.0 |
--------------------------------------------------------------------------------------------------
openldap         | LDAP           | http://www.openldap.org/                           |  2.4.24 |
--------------------------------------------------------------------------------------------------
impacket         | SMB            | http://code.google.com/p/impacket/                 | svn#525 |
--------------------------------------------------------------------------------------------------
cx_Oracle        | Oracle         | http://cx-oracle.sourceforge.net/                  |   5.1.1 |
--------------------------------------------------------------------------------------------------
mysql-python     | MySQL          | http://sourceforge.net/projects/mysql-python/      |   1.2.3 |
--------------------------------------------------------------------------------------------------
psycopg          | PostgreSQL     | http://initd.org/psycopg/                          |   2.4.5 |
--------------------------------------------------------------------------------------------------
pycrypto         | VNC            | http://www.dlitz.net/software/pycrypto/            |     2.3 |
--------------------------------------------------------------------------------------------------
dnspython        | DNS            | http://www.dnspython.org/                          |  1.10.0 |
--------------------------------------------------------------------------------------------------
pysnmp           | SNMP           | http://pysnmp.sourceforge.net/                     |   4.2.1 |
--------------------------------------------------------------------------------------------------
pyasn1           | SNMP           | http://sourceforge.net/projects/pyasn1/            |   0.1.2 |
--------------------------------------------------------------------------------------------------
IPy              | NETx keywords  | https://github.com/haypo/python-ipy                |    0.75 |
--------------------------------------------------------------------------------------------------
unzip            | ZIP passwords  | http://www.info-zip.org/                           |     6.0 |
--------------------------------------------------------------------------------------------------
Java             | keystore files | http://www.oracle.com/technetwork/java/javase/     |       6 |
--------------------------------------------------------------------------------------------------
python           |                | http://www.python.org/                             |     2.7 |
--------------------------------------------------------------------------------------------------

* Shortcuts (optionnal)
ln -s path/to/patator.py /usr/bin/ftp_login
ln -s path/to/patator.py /usr/bin/http_fuzz
so on ...


USAGE
-----

$ python patator.py <module> -h
or
$ <module> -h  (if you created the shortcuts)

There are global options and module options:
  - all global options start with - or --
  - all module options are of the form option=value

All module options are fuzzable:
---------
./module host=FILE0 port=FILE1 foobar=FILE2.google.FILE3 0=hosts.txt 1=ports.txt 2=foo.txt 3=bar.txt

The keywords (FILE, COMBO, NET, ...) act as place-holders. They indicate the type of wordlist
and where to replace themselves with the actual words to test.

Each keyword is numbered in order to:
  - match the corresponding wordlist
  - and indicate in what order to iterate over all the wordlists

For instance, this would be the classic order:
---------
$ ./module host=FILE0 user=FILE1 password=FILE2 0=hosts.txt 1=logins.txt 2=passwords.txt
10.0.0.1 root password
10.0.0.1 root 123456
10.0.0.1 root qsdfghj
... (trying all passwords before testing next login)
10.0.0.1 admin password
10.0.0.1 admin 123456
10.0.0.1 admin qsdfghj
... (trying all logins before testing next host)
10.0.0.2 root password
...

While a smarter way might be:
---------
$ ./module host=FILE2 user=FILE1 password=FILE0 2=hosts.txt 1=logins.txt 0=passwords.txt
10.0.0.1 root password
10.0.0.2 root password
10.0.0.1 admin password
10.0.0.2 admin password
10.0.0.1 root 123456
10.0.0.2 root 123456
10.0.0.1 admin 123456
...


* Keywords

Brute-force a list of hosts with a file containing combo entries (each line := login:password).
---------
./module host=FILE0 user=COMBO10 password=COMBO11 0=hosts.txt 1=combos.txt


Scan subnets to just grab version banners.
---------
./module host=NET0 0=10.0.1.0/24,10.0.2.0/24,10.0.3.128-10.0.3.255


* Actions & Conditions

Use the -x option to do specific actions upon receiving expected results. For instance:

To ignore responses with status code 200 *AND* a size within a range.
---------
./module host=10.0.0.1 user=FILE0 -x ignore:code=200,size=57-74

To ignore responses with status code 500 *OR* containing "Internal error".
---------
./module host=10.0.0.1 user=FILE0 -x ignore:code=500 -x ignore:fgrep='Internal error'

Remember that conditions are ANDed within the same -x option, use multiple -x options to
specify ORed conditions.


* Failures

During execution, failures may happen, such as a TCP connect timeout for
instance. A failure is actually an exception that the module does not expect,
and as a result the exception is caught upstream by the controller.

Such exceptions, or failures, are not immediately reported to the user, the
controller will retry 4 more times before reporting the failed payload with the
code "xxx" (--max-retries defaults to 4).


* Read carefully the following examples to get a good understanding of how patator works.
{{{ FTP

* Brute-force authentication. Do not report wrong passwords.
---------
ftp_login host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:mesg='Login incorrect.'

NB0. If you get errors like "500 OOPS: priv_sock_get_cmd", use -x ignore,reset,retry:code=500
     in order to retry the last login/password using a new TCP connection. Odd servers like vsftpd
     return this when they shut down the TCP connection (ie. max login attempts reached).

NB1. If you get errors like "too many connections from your IP address", try decreasing the number of
     threads, the server may be enforcing a maximum number of concurrent connections.

* Same as before, but stop testing a user after his password is found.
---------
ftp_login ... -x free=user:code=0


* Find anonymous FTP servers on a subnet.
---------
ftp_login host=NET0 user=anonymous password=test@example.com 0=10.0.0.0/24

}}}
{{{ SSH
* Brute-force authentication. Do not report wrong passwords.
---------
ssh_login host=10.0.0.1 user=FILE0 password=FILE0 0=logins.txt -x ignore:mesg='Authentication failed.'

NB. If you get errors like "Error reading SSH protocol banner ... Connection reset by peer",
    try decreasing the max_conn option (default is 10), the server may be enforcing a maximum
    number of concurrent connections (eg. MaxStartups in OpenSSH).


* Brute-force several hosts and stop testing a host after a valid password is found.
---------
ssh_login host=FILE0 user=FILE1 password=FILE2 0=hosts.txt 1=logins.txt 2=passwords.txt -x free=host:code=0


* Same as previous, but stop testing a user on a host after his password is found.
---------
ssh_login host=FILE0 user=FILE1 password=FILE2 0=hosts.txt 1=logins.txt 2=passwords.txt -x free=host+user:code=0

}}}
{{{ Telnet

* Brute-force authentication.
  (a) Enter login after first prompt is detected, enter password after second prompt.
  (b) The regex to detect the login and password prompts.
  (c) Reconnect when we get no login prompt back (max number of tries reached or successful login).
------------                    (a)
telnet_login host=10.0.0.1 inputs='FILE0\nFILE1' 0=logins.txt 1=passwords.txt
 prompt_re='tux login:|Password:' -x reset:egrep!='Login incorrect.+tux login:'
 (b)                             (c)
 
NB. If you get errors like "telnet connection closed", try decreasing the number of threads,
    the server may be enforcing a maximum number of concurrent connections.

}}}
{{{ SMTP

* Enumerate valid users using the VRFY command.
  (a) Do not report invalid recipients.
  (b) Do not report when the server shuts us down with "421 too many errors",
      reconnect and resume testing.
---------                                               (a)
smtp_vrfy host=10.0.0.1 user=FILE0 0=logins.txt -x ignore:fgrep='User unknown in local
 recipient table' -x ignore,reset,retry:code=421
                             (b)

* Use the RCPT TO command in case the VRFY command is not available.
---------
smtp_rcpt host=10.0.0.1 user=FILE0@localhost 0=logins.txt helo='ehlo mx.fb.com' mail_from=root


* Brute-force authentication.
  (a) Send a fake hostname (by default your host fqdn is sent)
------------             (a)
smtp_login host=10.0.0.1 helo='ehlo its.me.com' user=FILE0@dom.com password=FILE1 0=logins.txt 1=passwords.txt 

}}}
{{{ HTTP

* Find hidden web resources.
  (a) Use a specific header.
  (b) Follow redirects.
  (c) Do not report 404 errors.
  (d) Retry on 500 errors.
---------                                             (a)
http_fuzz url=http://localhost/FILE0 0=words.txt header='Cookie: SESSID=A2FD8B2DA4'
 follow=1 -x ignore:code=404 -x ignore,retry:code=500
 (b)            (c)                  (d)

NB. You may be able to go 10 times faster using webef (http://www.hsc.fr/ressources/outils/webef/).
    It is the fastest HTTP brute-forcer I know, yet at the moment it still lacks useful features
    that will prevent you from performing the following attacks.

* Brute-force phpMyAdmin logon.
  (a) Use POST requests.
  (b) Follow redirects using cookies sent by server.
  (c) Ignore failed authentications.
---------                                             (a)         (b)        (b)
http_fuzz url=http://10.0.0.1/phpmyadmin/index.php method=POST follow=1 accept_cookie=1 
 body='pma_username=root&pma_password=FILE0&server=1&lang=en' 0=passwords.txt
 -x ignore:fgrep='Cannot log in to the MySQL server'
             (c)

* Scan subnet for directory listings.
  (a) Ignore not matching reponses.
  (b) Save matching responses into directory.
---------
http_fuzz url=http://NET0/FILE1 0=10.0.0.0/24 1=dirs.txt -x ignore:fgrep!='Index of'
 -l /tmp/directory_listings                                             (a)
      (b)  

* Brute-force Basic authentication.
  (a) Single mode (login == password).
  (b) Do not report failed login attempts.
---------
http_fuzz url=http://10.0.0.1/manager/html user_pass=FILE0:FILE0 0=logins.txt -x ignore:code=401
                                                   (a)                                (b)

* Find hidden virtual hosts.
  (a) Read template from file.
  (b) Fuzz both the Host and User-Agent headers.
---------
echo -e 'Host: FILE0\nUser-Agent: FILE1' > headers.txt
http_fuzz url=http://10.0.0.1/ header=@headers.txt 0=vhosts.txt 1=agents.txt
                                    (a)                       (b)

* Brute-force logon using GET requests.
  (a) Encode everything surrounded by the two tags _@@_ in hexadecimal.
  (b) Ignore HTTP 200 responses with a content size (header+body) within given range
      and that also contain the given string.
  (c) Use a different delimiter string because the comma cannot be escaped.
---------                                                         (a)             (a)
http_fuzz url='http://10.0.0.1/login?username=admin&password=_@@_FILE0_@@_' -e _@@_:hex
 0=words.txt -x ignore:'code=200|size=1500-|fgrep=Welcome, unauthenticated user' -X '|'
                (b)                                                              (c)

* Brute-force logon that enforces two random nonces to be submitted along every POST.
  (a) First, request the page that provides the nonces as hidden input fields.
  (b) Use regular expressions to extract the nonces that are to be submitted along the main request.
---------
http_fuzz url=http://10.0.0.1/login method=POST body='user=admin&pass=FILE0&nonce1=_N1_&nonce2=_N2_' 0=passwords.txt accept_cookie=1
 before_urls=http://10.0.0.1/index before_egrep='_N1_:<input type="hidden" name="nonce1" value="(\w+)"|_N2_:name="nonce2" value="(\w+)"'
           (a)                                (b)

* Test the OPTIONS method against a list of URLs.
  (a) Ignore URLs that only allow the HEAD and GET methods.
  (b) Header end of line is '\r\n'.
  (c) Use a different delimiter string because the comma cannot be escaped.
---------
http_fuzz url=FILE0 0=urls.txt method=OPTIONS -x ignore:egrep='^Allow: HEAD, GET\r$' -X '|'
                                                            (a)                 (b)  (c)
}}}
{{{ LDAP

* Brute-force authentication.
  (a) Do not report wrong passwords.
  (b) Talk SSL/TLS to port 636.
---------
ldap_login host=10.0.0.1 binddn='cn=FILE0,dc=example,dc=com' 0=logins.txt bindpw=FILE1 1=passwords.txt
 -x ignore:mesg='ldap_bind: Invalid credentials (49)' ssl=1 port=636
         (a)                                              (b)
}}}
{{{ SMB

* Brute-force authentication.
---------
smb_login host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:fgrep=STATUS_LOGON_FAILURE

NB. If you suddenly get STATUS_ACCOUNT_LOCKED_OUT errors for an account
    although it is not the first password you test on this account, then you must
    have locked it.


* Pass-the-hash.
  (a) Test a list of hosts.
  (b) Test every user (each line := login:rid:LM hash:NT hash).
---------
smb_login host=FILE0 0=hosts.txt user=COMBO10 password_hash=COMBO12:COMBO13 1=pwdump.txt -x ...
             (a)                                         (b)
}}}
{{{ MSSQL

* Brute-force authentication.
-----------
mssql_login host=10.0.0.1 user=sa password=FILE0 0=passwords.txt -x ignore:fgrep='Login failed for user'

}}}
{{{ Oracle
Beware, by default in Oracle, accounts are permanently locked out after 10 wrong passwords,
except for the SYS account.

* Brute-force authentication.
------------
oracle_login host=10.0.0.1 user=SYS password=FILE0 0=passwords.txt sid=ORCL -x ignore:code=ORA-01017

NB0. With Oracle 10g XE (Express Edition), you do not need to pass a SID.

NB1. If you get ORA-12516 errors, it may be because you reached the limit of
     concurrent connections or db processes, try using "--rate-limit 0.5 -t 2" to be
     more polite. Also you can run "alter system set processes=150 scope=spfile;"
     and restart your database to get rid of this.


* Brute-force SID.
------------
oracle_login host=10.0.0.1 sid=FILE0 0=sids.txt -x ignore:code=ORA-12505

NB. Against Oracle9, it may crash (Segmentation fault) as soon as a valid SID is
    found (cx_Oracle bug). Sometimes, the SID gets printed out before the crash,
    so try running the same command again if it did not.

}}}
{{{ MySQL

* Brute-force authentication.
-----------
mysql_login host=10.0.0.1 user=FILE0 password=FILE0 0=logins.txt -x ignore:fgrep='Access denied for user'

}}}
{{{ PostgresSQL

* Brute-force authentication.
-----------
pgsql_login host=10.0.0.1 user=postgres password=FILE0 0=passwords.txt -x ignore:fgrep='password authentication failed'

}}}
{{{ VNC
Some VNC servers have built-in anti-bruteforce functionnality that temporarily
blacklists the attacker IP address after too many wrong passwords.
 - RealVNC-4.1.3 or TightVNC-1.3.10 for example, allow 5 failed attempts and
   then enforce a 10 second delay. For each subsequent failed attempt that
   delay is doubled.
 - RealVNC-3.3.7 or UltraVNC allow 6 failed attempts and then enforce a 10
   second delay between each following attempt.

* Brute-force authentication.
  (a) No need to use more than one thread.
  (b) Keep retrying the same password when we are blacklisted by the server.
  (c) Exit execution as soon as a valid password is found.
---------                                               (a)
vnc_login host=10.0.0.1 password=FILE0 0=passwords.txt --threads 1
 -x retry:fgrep!='Authentication failure' --max-retries -1 -x quit:code=0
        (b)                                 (b)                 (c)
}}}
{{{ DNS

* Brute-force subdomains.
  (a) Ignore NXDOMAIN responses (rcode 3).
-----------
dns_forward name=FILE0.google.com 0=names.txt -x ignore:code=3
                                              (a)
* Brute-force domain with every possible TLDs.
-----------
dns_forward name=google.MOD0 0=TLD -x ignore:code=3

* Brute-force SRV records.
-----------
dns_forward name=MOD0.microsoft.com 0=SRV qtype=SRV -x ignore:code=3

* Grab the version of several hosts.
-----------
dns_forward server=FILE0 0=hosts.txt name=version.bind qtype=txt qclass=ch

* Reverse lookup several networks.
  (a) Ignore names that do not contain 'google.com'.
  (b) Ignore generic PTR records.
-----------
dns_reverse host=NET0 0=216.239.32.0-216.239.47.255,8.8.8.0/24 -x ignore:code=3 -x ignore:fgrep!=google.com -x ignore:fgrep=216-239-
                                                                                (a)                         (b)
}}}
{{{ SNMP

* SNMPv1/2 : Find valid community names.
----------
snmp_login host=10.0.0.1 community=FILE0 1=names.txt -x ignore:mesg='No SNMP response received before timeout'


* SNMPv3 : Find valid usernames.
----------
snmp_login host=10.0.0.1 version=3 user=FILE0 0=logins.txt -x ignore:mesg=unknownUserName


* SNMPv3 : Find valid passwords.
----------
snmp_login host=10.0.0.1 version=3 user=myuser auth_key=FILE0 0=passwords.txt -x ignore:mesg=wrongDigest

NB0. If you get "notInTimeWindow" error messages, increase the retries option.
NB1. SNMPv3 requires passphrases to be at least 8 characters long.

}}}
{{{ Unzip

* Brute-force the ZIP file password (cracking older pkzip encryption used to be not supported in JtR).
----------
unzip_pass zipfile=path/to/file.zip password=FILE0 0=passwords.txt -x ignore:code!=0

}}}

CHANGELOG
---------

* v0.4 2012/11/02
  - new modules: smb_lookupsid, finger_lookup, pop_login, imap_login, vmauthd_login
  - improved connection cache
  - improved usage, user can now act upon specific reponses (eg. stop brute-forcing host if down, or stop testing login if password found)
  - improved dns brute-forcing presentation
  - switched to dnspython which is not limited to the IN class (eg. can now scan for {hostname,version}.bind)
  - rewrote itertools.product to avoid memory over-consumption when using large wordlists
  - can now read wordlist from stdin
  - added timeout option to most of the network brute-forcing modules
  - added SSL and/or TLS support to a few modules
  - before_egrep now allows more than one expression (ie. useful when more than one random nonce needs to be submitted)
  - fixed numerous bugs

* v0.3 2011/12/16
    - minor bugs fixed in http_fuzz
    - option -e better implemented
    - better warnings about missing dependencies

* v0.2 2011/12/01
    - new smtp_login module
    - several bugs fixed

* v0.1 2011/11/25 : Public release


TODO
----
  * new option -e ns like in Medusa (not likely to be implemented due to design)
  * replace dnspython|paramiko|IPy with a better module (scapy|libssh2|... ?)
'''

# }}}

# logging {{{
import logging
class MyLoggingFormatter(logging.Formatter):

  dft_fmt = '%(asctime)s %(name)-7s %(levelname)7s - %(message)s'
  dbg_fmt = '%(asctime)s %(name)-7s %(levelname)7s [%(threadName)s] %(message)s'

  def __init__(self):
    logging.Formatter.__init__(self, MyLoggingFormatter.dft_fmt, datefmt='%H:%M:%S')


  def format(self, record):
      if record.levelno == 10:   # DEBUG
          self._fmt = MyLoggingFormatter.dbg_fmt
      else:
          self._fmt = MyLoggingFormatter.dft_fmt

      return logging.Formatter.format(self, record)

handler = logging.StreamHandler()
handler.setFormatter(MyLoggingFormatter())
logger = logging.getLogger('patator')
logger.setLevel(logging.INFO)
logger.addHandler(handler)
# }}}

# imports {{{
import re
import os
from sys import stdin, exc_info, exit, version_info
from time import localtime, strftime, sleep, time
from functools import reduce
from threading import Thread, active_count, Lock
from select import select
from itertools import product, chain, islice
from string import ascii_lowercase
from binascii import hexlify
from base64 import b64encode
from datetime import timedelta, datetime
from struct import unpack
import socket
import subprocess
import hashlib
from collections import defaultdict
try:
  # python3+
  from queue import Queue, Empty, Full
  from urllib.parse import quote, urlencode, urlparse, urlunparse, parse_qsl, quote_plus
  from io import StringIO
except ImportError:
  # python2.6+
  from Queue import Queue, Empty, Full
  from urllib import quote, urlencode, quote_plus
  from urlparse import urlparse, urlunparse, parse_qsl
  from cStringIO import StringIO

warnings = []
try:
  from IPy import IP
  has_ipy = True
except ImportError:
  has_ipy = False
  warnings.append('IPy')

# imports }}}

# utils {{{
def which(program):
  def is_exe(fpath):
    return os.path.exists(fpath) and os.access(fpath, os.X_OK)

  fpath, fname = os.path.split(program)
  if fpath:
    if is_exe(program):
      return program
  else:
    for path in os.environ["PATH"].split(os.pathsep):
      exe_file = os.path.join(path, program)
      if is_exe(exe_file):
        return exe_file

  return None

def create_dir(top_path, from_stdin=False):
  top_path = os.path.abspath(top_path)
  if os.path.isdir(top_path):
    files = os.listdir(top_path)
    if files:
      if not from_stdin:
        if raw_input("Directory '%s' is not empty, do you want to wipe it ? [Y/n]: " % top_path) == 'n':
          exit(0)
      for root, dirs, files in os.walk(top_path):
        if dirs:
          print("Directory '%s' contains sub-directories, safely aborting..." % root)
          exit(0)
        for f in files:
          os.unlink(os.path.join(root, f))
        break
  else:
    os.mkdir(top_path)
  return top_path

def create_time_dir(top_path, desc):
  now = localtime()
  date, time = strftime('%Y-%m-%d', now), strftime('%H%M%S', now)
  top_path = os.path.abspath(top_path)
  date_path = os.path.join(top_path, date)
  time_path = os.path.join(top_path, date, time + '_' + desc)

  if not os.path.isdir(top_path):
    os.makedirs(top_path)
  if not os.path.isdir(date_path):
    os.mkdir(date_path)
  if not os.path.isdir(time_path):
    os.mkdir(time_path)

  return time_path

def pprint_seconds(seconds, fmt):
  return fmt % reduce(lambda x,y: divmod(x[0], y) + x[1:], [(seconds,),60,60])

def md5hex(plain):
  return hashlib.md5(plain).hexdigest()

def sha1hex(plain):
  return hashlib.sha1(plain).hexdigest()

# }}}

# Controller {{{
class Controller:

  builtin_actions = (
    ('ignore', 'do not report'),
    ('retry', 'try payload again'),
    ('free', 'dismiss future types of payloads'),
    ('quit', 'terminate execution now'),
    )

  available_encodings = {
    'hex': (hexlify, 'encode in hexadecimal'),
    'b64': (b64encode, 'encode in base64'),
    'md5': (md5hex, 'hash in md5'),
    'sha1': (sha1hex, 'hash in sha1'),
    'url': (quote_plus, 'url encode'),
    }

  def expand_key(self, arg):
    yield arg.split('=', 1)

  def find_file_keys(self, value):
    return map(int, re.findall(r'FILE(\d)', value))

  def find_net_keys(self, value):
    return map(int, re.findall(r'NET(\d)', value))

  def find_combo_keys(self, value):
    return [map(int, t) for t in re.findall(r'COMBO(\d)(\d)', value)]

  def find_module_keys(self, value):
    return map(int, re.findall(r'MOD(\d)', value))

  def usage_parser(self, name):
    from optparse import OptionParser
    from optparse import OptionGroup
    from optparse import IndentedHelpFormatter

    class MyHelpFormatter(IndentedHelpFormatter):
      def format_epilog(self, epilog):
        return epilog

      def format_heading(self, heading):
        if self.current_indent == 0 and heading == 'Options':
          heading = 'Global options'
        return "%*s%s:\n" % (self.current_indent, "", heading)

      def format_usage(self, usage):
        return '%s\nUsage: %s\n' % (__banner__, usage)

    available_actions = self.builtin_actions + self.module.available_actions
    available_conditions = self.module.Response.available_conditions

    usage = '''%%prog <module-options ...> [global-options ...]

Examples:
  %s''' % '\n  '.join(self.module.usage_hints)

    usage += '''

Module options:
%s ''' % ('\n'.join('  %-14s: %s' % (k, v) for k, v in self.module.available_options))
   
    epilog = '''
Syntax:
 -x actions:conditions

    actions    := action[,action]*
    action     := "%s"
    conditions := condition=value[,condition=value]*
    condition  := "%s"
''' % ('" | "'.join(k for k, v in available_actions), 
       '" | "'.join(k for k, v in available_conditions))

    epilog += '''
%s

%s
''' % ('\n'.join('    %-12s: %s' % (k, v) for k, v in available_actions),
       '\n'.join('    %-12s: %s' % (k, v) for k, v in available_conditions))

    epilog += '''
For example, to ignore all redirects to the home page:
... -x ignore:code=302,fgrep='Location: /home.html'

 -e tag:encoding

    tag        := any unique string (eg. T@G or _@@_ or ...)
    encoding   := "%s"

%s''' % ('" | "'.join(k for k in self.available_encodings),
       '\n'.join('    %-12s: %s' % (k, v) for k, (f, v) in self.available_encodings.items()))

    epilog += '''

For example, to encode every password in base64:
... host=10.0.0.1 user=admin password=_@@_FILE0_@@_ -e _@@_:b64

Please read the README inside for more examples and usage information.
'''

    parser = OptionParser(usage=usage, prog=name, epilog=epilog, version=__banner__, formatter=MyHelpFormatter())

    exe_grp = OptionGroup(parser, 'Execution')
    exe_grp.add_option('-x', dest='actions', action='append', default=[], metavar='arg', help='actions and conditions, see Syntax below')
    exe_grp.add_option('--start', dest='start', type='int', default=0, metavar='N', help='start from offset N in the wordlist product')
    exe_grp.add_option('--stop', dest='stop', type='int', default=None, metavar='N', help='stop at offset N')
    exe_grp.add_option('--resume', dest='resume', metavar='r1[,rN]*', help='resume previous run')
    exe_grp.add_option('-e', dest='encodings', action='append', default=[], metavar='arg', help='encode everything between two tags, see Syntax below')
    exe_grp.add_option('-C', dest='combo_delim', default=':', metavar='str', help="delimiter string in combo files (default is ':')")
    exe_grp.add_option('-X', dest='condition_delim', default=',', metavar='str', help="delimiter string in conditions (default is ',')")

    opt_grp = OptionGroup(parser, 'Optimization')
    opt_grp.add_option('--rate-limit', dest='rate_limit', type='float', default=0, metavar='N', help='wait N seconds between tests (default is 0)')
    opt_grp.add_option('--max-retries', dest='max_retries', type='int', default=4, metavar='N', help='skip payload after N failures (default is 4) (-1 for unlimited)')
    opt_grp.add_option('-t', '--threads', dest='num_threads', type='int', default=10, metavar='N', help='number of threads (default is 10)')

    log_grp = OptionGroup(parser, 'Logging')
    log_grp.add_option('-l', dest='log_dir', metavar='DIR', help="save output and response data into DIR ")
    log_grp.add_option('-L', dest='auto_log', metavar='SFX', help="automatically save into DIR/yyyy-mm-dd/hh:mm:ss_SFX (DIR defaults to '/tmp/patator')") 

    dbg_grp = OptionGroup(parser, 'Debugging')
    dbg_grp.add_option('-d', '--debug', dest='debug', action='store_true', default=False, help='enable debug messages')

    parser.option_groups.extend([exe_grp, opt_grp, log_grp, dbg_grp])

    return parser

  def parse_usage(self, argv):
    parser = self.usage_parser(argv[0])
    opts, args = parser.parse_args(argv[1:])

    if opts.debug:
      logger.setLevel(logging.DEBUG)

    if not len(args) > 0:
      parser.print_usage()
      print('ERROR: wrong usage. Please read the README inside for more information.')
      exit(2)

    return opts, args

  def __init__(self, module, argv):
    self.actions = {}
    self.free_list = []
    self.paused = False
    self.from_stdin = False
    self.start_time = 0
    self.total_size = 1
    self.stop_now = False
    self.log_dir = None
    self.thread_report = []
    self.thread_progress = []

    self.payload = {}
    self.iter_keys = {}
    self.enc_keys = []

    self.module = module
    opts, args = self.parse_usage(argv)

    self.combo_delim = opts.combo_delim
    self.condition_delim = opts.condition_delim
    self.rate_limit = opts.rate_limit
    self.max_retries = opts.max_retries
    self.num_threads = opts.num_threads
    self.start, self.stop, self.resume = opts.start, opts.stop, opts.resume

    wlists = {}
    kargs = []
    for arg in args: # ('host=NET0', '0=10.0.0.0/24', 'user=COMBO10', 'password=COMBO11', '1=combos.txt', 'name=google.MOD2', '2=TLD')
      for k, v in self.expand_key(arg):
        logger.debug('k: %s, v: %s' % (k, v))

        if k.isdigit():
          wlists[k] = v

          if v == '-':
            self.from_stdin = True

        else:
          if v.startswith('@'):
            p = os.path.expanduser(v[1:])
            v = open(p).read()
          kargs.append((k, v)) 

    iter_vals = [v for k, v in sorted(wlists.items())]
    logger.debug('kargs: %s' % kargs) # [('host', 'NET0'), ('user', 'COMBO10'), ('password', 'COMBO11'), ('domain', 'MOD2')]
    logger.debug('iter_vals: %s' % iter_vals) # ['10.0.0.0/24', 'combos.txt', 'TLD']

    for k, v in kargs:

      for e in opts.encodings:
        meta, enc = e.split(':')
        if re.search(r'{0}.+?{0}'.format(meta), v):
          self.enc_keys.append((k, meta, self.available_encodings[enc][0]))

      for i in self.find_file_keys(v):
        if i not in self.iter_keys:
          self.iter_keys[i] = ('FILE', iter_vals[i], [])
        self.iter_keys[i][2].append(k)

      else:
        for i in self.find_net_keys(v):
          if i not in self.iter_keys:
            self.iter_keys[i] = ('NET', iter_vals[i], [])
          self.iter_keys[i][2].append(k)

          if not has_ipy:
            logger.warn('IPy (https://github.com/haypo/python-ipy) is required for using NETx keywords.')
            logger.warn('Please read the README inside for more information.')
            exit(3)

        else:
          for i, j in self.find_combo_keys(v):
            if i not in self.iter_keys:
              self.iter_keys[i] = ('COMBO', iter_vals[i], [])
            self.iter_keys[i][2].append((j, k))
          
          else:
            for i in self.find_module_keys(v):
              if i not in self.iter_keys:
                self.iter_keys[i] = ('MOD', iter_vals[i], [])
              self.iter_keys[i][2].append(k)

            else:
              self.payload[k] = v

    logger.debug('iter_keys: %s' % self.iter_keys) # { 0: ('NET', '10.0.0.0/24', ['host']), 1: ('COMBO', 'combos.txt', [(0, 'user'), (1, 'password')]), 2: ('MOD', 'TLD', ['name'])
    logger.debug('enc_keys: %s' % self.enc_keys) # [('password', 'ENC', hexlify), ('header', 'B64', b64encode), ...
    logger.debug('payload: %s' % self.payload)

    self.available_actions = [k for k, _ in self.builtin_actions + self.module.available_actions]
    self.module_actions = [k for k, _ in self.module.available_actions]

    for x in opts.actions:
      self.update_actions(x)

    logger.debug('actions: %s' % self.actions)

    if opts.auto_log:
      self.log_dir = create_time_dir(opts.log_dir or '/tmp/patator', opts.auto_log)
    elif opts.log_dir:
      self.log_dir = create_dir(opts.log_dir, self.from_stdin)
    
    if self.log_dir:
      log_file = os.path.join(self.log_dir, 'RUNTIME.log')
      with open(log_file, 'w') as f:
        f.write('$ %s\n' % ' '.join(argv))

      handler = logging.FileHandler(log_file)
      handler.setFormatter(MyLoggingFormatter())
      logging.getLogger('patator').addHandler(handler)
    
  def update_actions(self, arg): 
    actions, conditions = arg.split(':', 1)

    for action in actions.split(','):

      conds = [c.split('=', 1) for c in conditions.split(self.condition_delim)]
     
      if '=' in action:
        name, opts = action.split('=')
      else:
        name, opts = action, None

      if name not in self.available_actions:
        raise NotImplementedError('Unsupported action: %s' % name)

      if name not in self.actions:
        self.actions[name] = []

      self.actions[name].append((conds, opts))

  def lookup_actions(self, resp):
    actions = {}
    for action, conditions in self.actions.items():
      for condition, opts in conditions:
        for key, val in condition:
          if key[-1] == '!':
            if resp.match(key[:-1], val):
              break
          else:
            if not resp.match(key, val):
              break
        else:
          actions[action] = opts
    return actions

  def check_free(self, payload):
    # free_list: 'host=10.0.0.1', 'user=anonymous', 'host=10.0.0.7,user=test', ...
    for m in self.free_list:
      args = m.split(',', 1)
      for arg in args:
        k, v = arg.split('=', 1)
        if payload[k] != v:
          break
      else:
        return True

    return False

  def register_free(self, payload, opts):
    self.free_list.append(','.join('%s=%s' % (k, payload[k]) for k in opts.split('+')))
    logger.debug('free_list updated: %s' % self.free_list)
  
  def fire(self):
    logger.info('Starting %s at %s' % (__banner__, strftime('%Y-%m-%d %H:%M %Z', localtime())))

    try:
      tryok = False
      self.start_threads()
      self.monitor_progress()
      tryok = True
    except SystemExit:
      logger.info('Quitting')
    except KeyboardInterrupt:
      print
    except:
      logger.exception(exc_info()[1])

    if not tryok:
      self.stop_now = True
      try:
        while active_count() > 1:
          sleep(.1)
      except KeyboardInterrupt:
        pass

    self.report_progress()

    hits_count = sum(p.hits_count for p in self.thread_progress)
    done_count = sum(p.done_count for p in self.thread_progress)
    skip_count = sum(p.skip_count for p in self.thread_progress)
    fail_count = sum(p.fail_count for p in self.thread_progress)

    total_time = time() - self.start_time
    speed_avg = done_count / total_time 

    if self.from_stdin:
      if tryok:
        self.total_size = done_count+skip_count
      else:
        self.total_size = -1

    self.show_final()

    logger.info('Hits/Done/Skip/Fail/Size: %d/%d/%d/%d/%d, Avg: %d r/s, Time: %s' % (
      hits_count, done_count, skip_count, fail_count, self.total_size, speed_avg,
      pprint_seconds(total_time, '%dh %dm %ds')))

    if not tryok:
      resume = []
      for i, p in enumerate(self.thread_progress):
        c = p.done_count + p.skip_count
        if self.resume:
          if i < len(self.resume):
            c += self.resume[i]
        resume.append(str(c))
        
      logger.info('To resume execution, pass --resume %s' % ','.join(resume))

  def push_final(self, resp): pass
  def show_final(self): pass

  def start_threads(self):

    class Progress:
      def __init__(self):
        self.current = ''
        self.done_count = 0
        self.hits_count = 0
        self.skip_count = 0
        self.fail_count = 0
        self.seconds = [1]*25 # avoid division by zero early bug condition

    gqueues = [Queue(maxsize=10000) for _ in range(self.num_threads)]

    # consumers
    for num in range(self.num_threads):
      pqueue = Queue()
      t = Thread(target=self.consume, args=(gqueues[num], pqueue))
      t.daemon = True
      t.start()
      self.thread_report.append(pqueue)
      self.thread_progress.append(Progress())

    # producer
    t = Thread(target=self.produce, args=(gqueues,))
    t.daemon = True
    t.start()

  def produce(self, queues):

    if self.from_stdin:
      from itertools import product, chain

    else:
      def product(xs, *rest):
        if len(rest) == 0:
          for x in xs():
            yield [x]
        else:
          for head in xs():
            for tail in product(*rest):
              yield [head] + tail

      def chain(*iterables):
        def xs():
          for iterable in iterables:
            for element in iterable:
              yield element
        return xs

    class FileIter:
      def __init__(self, filename):
        self.filename = filename

      def __iter__(self):
        return open(self.filename)

    iterables = []
    for _, (t, v, _) in self.iter_keys.items():

      if t in ('FILE', 'COMBO'):
        size = 0
        files = []

        for fname in v.split(','):
          if fname == '-': # stdin
            from sys import maxint
            size += maxint
            files.append(stdin)

          else:
            fpath = os.path.expanduser(fname)
            size += sum(1 for _ in open(fpath))
            files.append(FileIter(fpath))

        iterable = chain(*files)

      elif t == 'NET':
        subnets = [IP(n, make_net=True) for n in v.split(',')]
        size = sum(len(s) for s in subnets)
        iterable = chain(*subnets)

      elif t == 'MOD':
        elements, size = self.module.available_keys[v]()
        iterable = chain(elements)

      else:
        raise NotImplementedError("Incorrect keyword '%s'" % t)

      self.total_size *= size
      iterables.append(iterable)

    if self.stop:
      self.total_size = self.stop - self.start 
    else:
      self.total_size -= self.start

    if self.resume:
      self.resume = [int(i) for i in self.resume.split(',')]
      self.total_size -= sum(self.resume)

    logger.info('')
    logger.info('%-15s | %-25s \t | %5s | %s' % ('code & size', 'candidate', 'num', 'mesg'))
    logger.info('-' * 63)

    self.start_time = time()
    count = 0
    for pp in islice(product(*iterables), self.start, self.stop):

      cid = count % self.num_threads
      prod = [str(p).strip('\r\n') for p in pp]

      if self.resume:
        idx = count % len(self.resume)
        off = self.resume[idx]

        if count < off * len(self.resume):
          logger.debug('Skipping %d %s, resume[%d]: %s' % (count, ':'.join(prod), idx, self.resume[idx]))
          count += 1
          continue

      while True:
        if self.stop_now:
          return

        try:
          queues[cid].put_nowait(prod)
          break
        except Full:
          sleep(.1)

      count += 1

    for q in queues:
      q.put(None)

  def consume(self, gqueue, pqueue):
    module = self.module()

    def shutdown():
      logger.debug('thread exits')
      if hasattr(module, '__del__'):
        module.__del__()

    while True:
      if self.stop_now:
        shutdown()
        return

      prod = gqueue.get()
      if prod is None:
        shutdown()
        return
      
      payload = self.payload.copy()
 
      for i, (t, _, keys) in self.iter_keys.items():
        if t == 'FILE':
          for k in keys:
            payload[k] = payload[k].replace('FILE%d' % i, prod[i])
        elif t == 'NET':
          for k in keys:
            payload[k] = payload[k].replace('NET%d' % i, prod[i])
        elif t == 'COMBO':
          for j, k in keys: 
            payload[k] = payload[k].replace('COMBO%d%d' % (i, j), prod[i].split(self.combo_delim)[j])
        elif t == 'MOD':
          for k in keys:
            payload[k] = payload[k].replace('MOD%d' %i, prod[i])

      for k, m, e in self.enc_keys:
        payload[k] = re.sub(r'{0}(.+?){0}'.format(m), lambda m: e(m.group(1)), payload[k])
  
      logger.debug('product: %s' % prod)
      pp_prod = ':'.join(prod)

      if self.check_free(payload):
        pqueue.put_nowait(('skip', pp_prod, None, 0))
        continue

      try_count = 0
      start_time = time() 

      while True:

        while self.paused and not self.stop_now:
          sleep(1)

        if self.stop_now:
          shutdown()
          return

        if self.rate_limit:
          sleep(self.rate_limit)


        if try_count <= self.max_retries or self.max_retries < 0:

          actions = {}
          try_count += 1

          logger.debug('payload: %s [try %d/%d]' % (payload, try_count, self.max_retries+1))

          try:
            resp = module.execute(**payload)

          except:
            e_type, e_value, _ = exc_info()
            mesg = '%s %s' % (e_type, e_value.args)

            #logger.exception(exc_info()[1])

            logger.debug('except: %s' % mesg)
            resp = self.module.Response('xxx', mesg)

            if hasattr(module, 'reset'):
              module.reset()

            continue

        else:
          actions = {'fail': None}

        actions.update(self.lookup_actions(resp))
        pqueue.put_nowait((actions, pp_prod, resp, time() - start_time))

        for name in self.module_actions:
          if name in actions:
            getattr(module, name)(**payload)

        if 'free' in actions:
          self.register_free(payload, actions['free'])
          break

        if 'fail' in actions:
          break

        if 'retry' in actions:
          continue

        break
       
  def monitor_progress(self):
    while active_count() > 1:
      self.report_progress()

      if not self.from_stdin:
        self.monitor_interaction()

  def report_progress(self):
    for i, pq in enumerate(self.thread_report):
      p = self.thread_progress[i]

      while True:

        try:
          actions, current, resp, seconds = pq.get_nowait()
          #logger.debug('actions reported: %s' % actions)

        except Empty: 
          break

        if actions == 'skip':
          p.skip_count += 1
          continue

        offset = (self.start + p.done_count * self.num_threads) + i + 1
        p.current = current
        p.seconds[p.done_count % len(p.seconds)] = seconds

        if 'ignore' not in actions:
          p.hits_count += 1
          logger.info('%-15s | %-25s \t | %5d | %s' % (resp.compact(), current, offset, resp))

          if self.log_dir:
            filename = '%d_%s' % (offset, resp.compact().replace(' ', '_'))
            with open('%s/%s.txt' % (self.log_dir, filename), 'w') as f:
              f.write(resp.dump())

          self.push_final(resp)

        if 'retry' not in actions:
          p.done_count += 1

        if 'fail' in actions:
          p.fail_count += 1

        if 'quit' in actions and 'retry' not in actions:
          raise SystemExit


  def monitor_interaction(self):

    i, _, _ = select([stdin], [], [], .1)
    if not i: return
    command = i[0].readline().strip()

    if command == 'h':
      logger.info('''Available commands:
       h       show help
       <Enter> show progress
       d/D     increase/decrease debug level
       p       pause progress
       f       show verbose progress
       x arg   add monitor condition
       a       show all active conditions
       q       terminate execution now
       ''')

    elif command == 'q':
      raise KeyboardInterrupt

    elif command == 'p':
      self.paused = not self.paused
      logger.info(self.paused and 'Paused' or 'Unpaused')

    elif command == 'd':
      logger.setLevel(logging.DEBUG)

    elif command == 'D':
      logger.setLevel(logging.INFO)

    elif command == 'a':
      logger.info(self.actions)

    elif command.startswith('x'):
      _, arg = command.split(' ', 1)
      self.update_actions(arg)

    else: # show progress
      total_count = sum(p.done_count+p.skip_count for p in self.thread_progress)
      speed_avg = self.num_threads / (sum(sum(p.seconds) / len(p.seconds) for p in self.thread_progress) / self.num_threads)
      remain_seconds = (self.total_size - total_count) / speed_avg
      etc_time = datetime.now() + timedelta(seconds = remain_seconds)

      logger.info('Progress: {0:>3}% ({1}/{2}) | Speed: {3:.0f} r/s | ETC: {4} ({5} remaining) {6}'.format(
        total_count * 100/self.total_size,
        total_count,
        self.total_size,
        speed_avg,
        etc_time.strftime('%H:%M:%S'),
        pprint_seconds(remain_seconds, '%02d:%02d:%02d'),
        self.paused and '| Paused' or ''))

      if command == 'f':
        for i, p in enumerate(self.thread_progress):
          total_count = p.done_count + p.skip_count
          logger.info(' {0:>3}: {1:>3}% ({2}/{3}) {4}'.format(
            '#%d' % (i+1),
            int(100*total_count/(1.0*self.total_size/self.num_threads)),
            total_count,
            self.total_size/self.num_threads,
            p.current))

# }}}

# Response_Base {{{
def match_size(size, val):
  if '-' in val:
    size_min, size_max = val.split('-')

    if not size_min and not size_max:
      raise ValueError('Invalid interval')

    elif not size_min: # size == -N
      return size <= int(size_max)

    elif not size_max: # size == N-
      return size >= int(size_min)

    else:
      size_min, size_max = int(size_min), int(size_max)
      if size_min >= size_max:
        raise ValueError('Invalid interval')

      return size_min <= size <= size_max

  else:
    return size == int(val)

class Response_Base:

  available_conditions = (
    ('code', 'match status code'),
    ('size', 'match size (N or N-M or N- or -N)'),
    ('mesg', 'match message'),
    ('fgrep', 'search for string'),
    ('egrep', 'search for regex'),
    )

  def __init__(self, code, mesg, trace=None):
    self.code = code
    self.mesg = mesg
    self.trace = trace
    self.size = len(self.mesg)

  def compact(self):
    return '%s %d' % (self.code, self.size)

  def __str__(self):
    return self.mesg

  def match(self, key, val):
    return getattr(self, 'match_'+key)(val)

  def match_code(self, val):
    return val == str(self.code)

  def match_size(self, val):
    return match_size(self.size, val)

  def match_mesg(self, val):
    return val == self.mesg

  def match_fgrep(self, val):
    return val in str(self)

  def match_egrep(self, val):
    return re.search(val, str(self))

  def dump(self):
    return self.trace or str(self)

# }}}

# TCP_Cache {{{
class TCP_Connection:

  def __init__(self, fp, banner=None):
    self.fp = fp
    self.banner = banner

  def close(self):
    self.fp.close()

class TCP_Cache:

  available_actions = (
    ('reset', 'close current connection in order to reconnect next time'),
    )

  available_options = (
    ('persistent', 'use persistent connections [1|0]'),
    )

  def __init__(self):
    self.cache = {}
    self.conn = None

  def __del__(self):
    for _, c in self.cache.items():
      c.close()

  def bind(self, *args, **kwargs):
    # *args identify one connection in the cache while **kwargs are only options
    key = ':'.join(args)
    if key not in self.cache:
      self.conn = self.cache[key] = self.connect(*args, **kwargs)
    else:
      self.conn = self.cache[key]

    return self.conn.fp, self.conn.banner

  def reset(self, **kwargs):
    if self.conn:
      for k, v in self.cache.items():
        if v == self.conn:
          del self.cache[k]
          break

      self.conn.close()
      self.conn = None

# }}}

# FTP {{{
from ftplib import FTP, Error as FTP_Error
try:
  from ftplib import FTP_TLS # New in python 2.7
except ImportError:
  logger.warn('TLS support to FTP was implemented in python 2.7')

class FTP_login(TCP_Cache):
  '''Brute-force FTP'''

  usage_hints = (
    """%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt"""
    """ -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500""",
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [21]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('tls', 'use TLS [0|1]'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, tls, timeout):

    if tls == '0':
      fp = FTP(timeout=int(timeout))
    else:
      fp = FTP_TLS(timeout=int(timeout))

    banner = fp.connect(host, int(port))

    return TCP_Connection(fp, banner)

  def execute(self, host, port='21', tls='0', user=None, password=None, timeout='10', persistent='1'):

    fp, resp = self.bind(host, port, tls, timeout=timeout)

    try:
      if user is not None:
        resp = fp.sendcmd('USER ' + user)
      if password is not None:
        resp = fp.sendcmd('PASS ' + password)

      logger.debug('No error: %s' % resp)
      self.reset()

    except FTP_Error as e: 
      resp = str(e)
      logger.debug('FTP_Error: %s' % resp)

    if persistent == '0':
      self.reset()

    code, mesg = resp.split(' ', 1)
    return self.Response(code, mesg)

# }}}

# SSH {{{
try:
  import paramiko 
  l = logging.getLogger('paramiko.transport')
  l.setLevel(logging.CRITICAL)
  l.addHandler(handler)
except ImportError:
  warnings.append('paramiko')

class SSH_Connection(TCP_Connection):

  def __init__(self, host, port, user, fp):
    self.host = host
    self.port = port
    self.fp = fp
    self.banner = fp.remote_version

    self.user = user
    self.ctime = time()

class SSH_Cache(TCP_Cache):

  lock = Lock()
  count = {} # '10.0.0.1:22': 9, '10.0.0.2:222': 10

  def __del__(self):
    for k, pool in self.cache.items():
      for u, c in pool.items():
        with self.lock:
          self.count[k] -= 1
        c.close()

  def bind(self, host, port, user, max_conn):

    hp = '%s:%s' % (host, port)
    if hp not in self.cache:
      self.cache[hp] = {}

      with self.lock:
        if hp not in self.count:
          self.count[hp] = 0

    while True:
      with self.lock:
        if self.count[hp] < int(max_conn):
          if user not in self.cache[hp]:
            self.count[hp] += 1
          break

      if self.cache[hp]:
        candidates = [(k, c.ctime) for k, c in self.cache[hp].items() if k != user]
        if candidates:
          u, _ = min(candidates, key=lambda x: x[1])
          c = self.cache[hp].pop(u)
          c.close()
        break

    if user not in self.cache[hp]:
      self.conn = self.cache[hp][user] = self.connect(host, port, user)
    else:
      self.conn = self.cache[hp][user]

    return self.conn.fp, self.conn.banner

  def reset(self, **kwargs):
    if self.conn:
      hp = '%s:%s' % (self.conn.host, self.conn.port)

      if self.conn.user in self.cache[hp]:
        with self.lock:
          self.count[hp] -= 1

        self.cache[hp].pop(self.conn.user)

      self.conn.close()
      self.conn = None

class SSH_login(SSH_Cache):
  '''Brute-force SSH'''

  usage_hints = (
    """%prog host=10.0.0.1 user=root password=FILE0 0=passwords.txt -x ignore:mesg='Authentication failed.'""",
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [22]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('auth_type', 'auth type to use [password|keyboard-interactive]'),
    ('max_conn', 'maximum concurrent connections per host:port [10]'),
    )
  available_options += SSH_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, user):
    fp = paramiko.Transport('%s:%s' % (host, int(port)))
    fp.start_client()

    return SSH_Connection(host, port, user, fp)

  def execute(self, host, port='22', user=None, password=None, auth_type='password', persistent='1', max_conn='10'):

    fp, banner = self.bind(host, port, user, max_conn)

    try:
      if user is not None and password is not None:
        if auth_type == 'password':
          fp.auth_password(user, password, fallback=False)

        elif auth_type == 'keyboard-interactive':
          fp.auth_interactive(user, lambda a,b,c: [password] if len(c) == 1 else [])

        else:
          raise NotImplementedError("Incorrect auth_type '%s'" % auth_type)

      logger.debug('No error')
      code, mesg = '0', banner

      self.reset()

    except paramiko.AuthenticationException as e:
      logger.debug('AuthenticationException: %s' % e)
      code, mesg = '1', str(e)

    if persistent == '0':
      self.reset()

    return self.Response(code, mesg)

# }}}

# Telnet {{{
from telnetlib import Telnet
class Telnet_login(TCP_Cache):
  '''Brute-force Telnet'''

  usage_hints = (
    """%prog host=10.0.0.1 inputs='FILE0\\nFILE1' 0=logins.txt 1=passwords.txt persistent=0"""
    """ prompt_re='Username:|Password:' -x ignore:egrep='Login incorrect.+Username:'""",
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [23]'),
    ('inputs', 'list of values to input'),
    ('prompt_re', 'regular expression to match prompts [\w+]'),
    ('timeout', 'seconds to wait for a response and for prompt_re to match received data [20]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, timeout):
    self.prompt_count = 0
    fp = Telnet(host, int(port), int(timeout))

    return TCP_Connection(fp)

  def execute(self, host, port='23', inputs=None, prompt_re='\w+:', timeout='20', persistent='1'):

    fp, _ = self.bind(host, port, timeout=timeout)

    trace = ''
    timeout = int(timeout)

    if self.prompt_count == 0:
      _, _, raw = fp.expect([prompt_re], timeout=timeout)
      logger.debug('raw banner: %s' % repr(raw))
      trace += raw
      self.prompt_count += 1
  
    if inputs is not None:
      for val in inputs.split(r'\n'):
        logger.debug('input: %s' % val)
        cmd = val + '\n' #'\r\x00'
        fp.write(cmd)
        trace += cmd

        _, _, raw = fp.expect([prompt_re], timeout=timeout)
        logger.debug('raw %d: %s' % (self.prompt_count, repr(raw)))
        trace += raw
        self.prompt_count += 1

    if persistent == '0':
      self.reset()

    mesg = repr(raw)[1:-1] # strip enclosing single quotes
    return self.Response(0, mesg, trace)

# }}}

# SMTP {{{
from smtplib import SMTP, SMTP_SSL, SMTPAuthenticationError, SMTPHeloError, SMTPException
class SMTP_Base(TCP_Cache):

  available_options = TCP_Cache.available_options
  available_options += (
    ('timeout', 'seconds to wait for a response [10]'),
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [25]'),
    ('ssl', 'use SSL [0|1]'),
    ('helo', 'helo or ehlo command to send after connect [skip]'),
    ('starttls', 'send STARTTLS [0|1]'),
    ('user', 'usernames to test'),
    )

  Response = Response_Base

  def connect(self, host, port, ssl, helo, starttls, timeout):

    if ssl == '0':
      if not port: port = 25
      fp = SMTP(timeout=int(timeout))
    else:
      if not port: port = 465
      fp = SMTP_SSL(timeout=int(timeout))

    resp = fp.connect(host, int(port))

    if helo:
      cmd, name = helo.split(' ', 1)
      
      if cmd.lower() == 'ehlo':
        resp = fp.ehlo(name)
      else:
        resp = fp.helo(name)

    if not starttls == '0':
      resp = fp.starttls()

    return TCP_Connection(fp, resp)
    

class SMTP_vrfy(SMTP_Base):
  '''Enumerate valid users using SMTP VRFY'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 0=logins.txt [helo='ehlo its.me.com']'''
    ''' -x ignore:fgrep='User unknown' -x ignore,reset,retry:code=421''',
    )

  def execute(self, host, port='', ssl='0', helo='', starttls='0', user=None, timeout='10', persistent='1'):

    fp, resp = self.bind(host, port, ssl, helo, starttls, timeout=timeout)

    if user is not None:
      resp = fp.verify(user)

    if persistent == '0':
      self.reset()

    code, mesg = resp
    return self.Response(code, mesg)


class SMTP_rcpt(SMTP_Base):
  '''Enumerate valid users using SMTP RCPT TO'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0@localhost 0=logins.txt [helo='ehlo its.me.com']'''
    ''' [mail_from=bar@example.com] -x ignore:fgrep='User unknown' -x ignore,reset,retry:code=421''',
    )

  available_options = SMTP_Base.available_options
  available_options += (
    ('mail_from', 'sender email [test@example.org]'),
    )

  def execute(self, host, port='', ssl='0', helo='', starttls='0', mail_from='test@example.org', user=None, timeout='10', persistent='1'):

    fp, resp = self.bind(host, port, ssl, helo, starttls, timeout=timeout)

    if mail_from:
      resp = fp.mail(mail_from)

    if user:
      resp = fp.rcpt(user)

    fp.rset()

    if persistent == '0':
      self.reset()

    code, mesg = resp
    return self.Response(code, mesg)


class SMTP_login(SMTP_Base):
  '''Brute-force SMTP'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=f.bar@dom.com password=FILE0 0=passwords.txt [helo='ehlo its.me.com']'''
    ''' -x ignore:fgrep='Authentication failed' -x ignore,reset,retry:code=421''',
    )

  available_options = SMTP_Base.available_options
  available_options += (
    ('password', 'passwords to test'),
    )

  def execute(self, host, port='', ssl='0', helo='', starttls='0', user=None, password=None, timeout='10', persistent='1'):

    fp, resp = self.bind(host, port, ssl, helo, starttls, timeout=timeout)
    
    try:
      if user is not None and password is not None:
        resp = fp.login(user, password)

      logger.debug('No error: %s' % resp)
      self.reset()

    except (SMTPHeloError,SMTPAuthenticationError,SMTPException) as resp:
      logger.debug('SMTPError: %s' % resp)

    if persistent == '0':
      self.reset()

    code, mesg = resp
    return self.Response(code, mesg)

# }}}

# Finger {{{
class Controller_Finger(Controller):

  user_list = []

  def push_final(self, resp):
    if hasattr(resp, 'lines'):
      for l in resp.lines:
         if l not in self.user_list:
           self.user_list.append(l)

  def show_final(self):
    print('\n'.join(self.user_list))

class Finger_lookup:
  '''Enumerate valid users using Finger'''

  usage_hints = (
    """%prog host=10.0.0.1 user=FILE0 0=words.txt -x ignore:fgrep='no such user'""",
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [79]'),
    ('user', 'usernames to test'),
    ('timeout', 'seconds to wait for a response [5]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='79', user='', timeout='5'):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(int(timeout))

    s.connect((host, int(port)))
    if user:
      s.send(user)
    s.send('\r\n')

    data = ''
    while True:
      raw = s.recv(1024)
      if not raw:
        break
      data += raw

    s.close()

    logger.debug('recv: %s' % repr(data))

    data = data.strip()
    mesg = repr(data)

    resp = self.Response(0, mesg, data)
    resp.lines = [l.strip('\r\n') for l in data.split('\n')]

    return resp
# }}}

# LDAP {{{
if not which('ldapsearch'):
  warnings.append('openldap')

# Because python-ldap-2.4.4 did not allow using a PasswordPolicyControl
# during bind authentication (cf. http://article.gmane.org/gmane.comp.python.ldap/1003),
# I chose to wrap around ldapsearch with "-e ppolicy".

class LDAP_login:
  '''Brute-force LDAP'''

  usage_hints = (
    """%prog host=10.0.0.1 binddn='cn=Directory Manager' bindpw=FILE0 0=passwords.txt"""
    """ -x ignore:mesg='ldap_bind: Invalid credentials (49)'""",
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [389]'),
    ('binddn', 'usernames to test'),
    ('bindpw', 'passwords to test'),
    ('basedn', 'base DN for search'),
    ('ssl', 'use SSL/TLS [0|1]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='389', binddn='', bindpw='', basedn='', ssl='0'):
    uri = 'ldap%s://%s:%s' % ('s' if ssl != '0' else '', host, port)
    cmd = ['ldapsearch', '-H', uri, '-e', 'ppolicy', '-D', binddn, '-w', bindpw, '-b', basedn]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'LDAPTLS_REQCERT': 'never'})
    out = p.stdout.read()
    err = p.stderr.read()

    code = p.wait()
    mesg = repr((out + err).strip())[1:-1]
    trace = '[out]\n%s\n[err]\n%s' % (out, err)

    return self.Response(code, mesg, trace)

# }}}

# SMB {{{
try:
  from impacket import smb as impacket_smb
  from impacket.dcerpc import dcerpc, transport, lsarpc
except ImportError:
  warnings.append('impacket')

class SMB_Connection(TCP_Connection):

  def close(self):
    self.fp.get_socket().close()

class SMB_login(TCP_Cache):
  '''Brute-force SMB'''

  usage_hints = (
    """%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt"""
    """ -x ignore:fgrep=STATUS_LOGON_FAILURE""",
    )
  
  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [139]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('password_hash', "LM/NT hashes to test, at least one hash must be provided ('lm:nt' or ':nt' or 'lm:')"),
    ('domain', 'domains to test'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  # ripped from medusa smbnt.c
  error_map = {
    0xFF: 'UNKNOWN_ERROR_CODE',
    0x00: 'STATUS_SUCCESS',
    0x0D: 'STATUS_INVALID_PARAMETER',
    0x5E: 'STATUS_NO_LOGON_SERVERS',
    0x6D: 'STATUS_LOGON_FAILURE',
    0x6E: 'STATUS_ACCOUNT_RESTRICTION',
    0x6F: 'STATUS_INVALID_LOGON_HOURS',
    0x70: 'STATUS_INVALID_WORKSTATION',
    0x71: 'STATUS_PASSWORD_EXPIRED',
    0x72: 'STATUS_ACCOUNT_DISABLED',
    0x5B: 'STATUS_LOGON_TYPE_NOT_GRANTED',
    0x8D: 'STATUS_TRUSTED_RELATIONSHIP_FAILURE',
    0x93: 'STATUS_ACCOUNT_EXPIRED',
    0x24: 'STATUS_PASSWORD_MUST_CHANGE',
    0x34: 'STATUS_ACCOUNT_LOCKED_OUT',
    0x01: 'AS400_STATUS_LOGON_FAILURE',
  }
  
  def connect(self, host, port):
    # if port == 445, impacket will use <host> instead of '*SMBSERVER' as the remote_name
    fp = impacket_smb.SMB('*SMBSERVER', host, sess_port=int(port))

    return SMB_Connection(fp)

  def execute(self, host, port='139', user=None, password=None, password_hash=None, domain='', persistent='1'):

    fp, _ = self.bind(host, port)

    try:
      if user is not None:
        if password is not None:
          fp.login(user, password, domain)

        else:
          lmhash, nthash = password_hash.split(':')
          fp.login(user, '', domain, lmhash, nthash)

      logger.debug('No error')
      code, mesg = '0', fp.get_server_name()

      self.reset()

    except impacket_smb.SessionError as e:
      code = '%x-%x' % (e.error_class, e.error_code)
      mesg = self.error_map.get(e.error_code, '')

      error_class = e.error_classes.get(e.error_class, None) # (ERRNT, {})
      if error_class:
        class_str = error_class[0] # 'ERRNT'
        error_tuple = error_class[1].get(e.error_code, None) # ('ERRnoaccess', 'Access denied.') or None

        if error_tuple:
          mesg += ' - %s %s' % error_tuple
        else:
          mesg += ' - %s' % class_str

    if persistent == '0':
      self.reset()

    return self.Response(code, mesg)


class DCE_Connection(TCP_Connection):

  def __init__(self, fp, smbt):
    self.fp = fp
    self.smbt = smbt

  def close(self):
    self.smbt.get_socket().close()

class SMB_lookupsid(TCP_Cache):
  '''Brute-force SMB SID-lookup'''

  usage_hints = (
    '''seq 500 2000 | %prog host=10.0.0.1 sid=S-1-5-21-1234567890-1234567890-1234567890 rid=FILE0 0=- -x ignore:code=1''',
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [139]'),
    ('sid', 'SID to test'),
    ('rid', 'RID to test'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, user, password):
    smbt = transport.SMBTransport(host, int(port), r'\lsarpc', user, password)

    dce = dcerpc.DCERPC_v5(smbt)
    dce.connect()
    dce.bind(lsarpc.MSRPC_UUID_LSARPC)

    fp = lsarpc.DCERPCLsarpc(dce)
    return DCE_Connection(fp, smbt)

  # http://msdn.microsoft.com/en-us/library/windows/desktop/hh448528%28v=vs.85%29.aspx
  SID_NAME_USER = [0, 'User', 'Group', 'Domain', 'Alias', 'WellKnownGroup', 'DeletedAccount', 'Invalid', 'Unknown', 'Computer', 'Label']

  def execute(self, host, port='139', user='', password='', sid=None, rid=None, persistent='1'):

    fp, _ = self.bind(host, port, user, password)

    if rid:
      sid = '%s-%s' % (sid, rid)

    op2 = fp.LsarOpenPolicy2('\\', access_mask=0x02000000)
    res = fp.LsarLookupSids(op2['ContextHandle'], [sid])

    if res['ErrorCode'] == 0:
      code, names = 0, []

      for d in res.formatDict():

        if 'types' in d: # http://code.google.com/p/impacket/issues/detail?id=10
          names.append(','.join('%s\\%s (%s)' % (d['domain'], n, self.SID_NAME_USER[t]) for n, t in zip(d['names'], d['types'])))
        else:
          names.append(','.join('%s\\%s' % (d['domain'], n) for n in d['names']))

    else:
      code, names = 1, ['unknown'] # STATUS_SOME_NOT_MAPPED

    if persistent == '0':
      self.reset()

    return self.Response(code, ', '.join(names))
# }}}

# POP {{{
from poplib import POP3, POP3_SSL, error_proto as pop_error
class POP_Connection(TCP_Connection):
  def close(self):
    self.fp.quit()

class POP_login(TCP_Cache):
  '''Brute-force POP3'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:code=-ERR''',
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [110]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('ssl', 'use SSL [0|1]'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, ssl, timeout):
    if ssl == '0':
      if not port: port = 110
      fp = POP3(host, int(port), timeout=int(timeout))
    else:
      if not port: port = 995
      fp = POP3_SSL(host, int(port)) # timeout=int(timeout)) # no timeout option in python2

    return POP_Connection(fp, fp.welcome)

  def execute(self, host, port='', ssl='0', user=None, password=None, timeout='10', persistent='1'):

    fp, resp = self.bind(host, port, ssl, timeout=timeout)

    try:
      if user is not None:
        resp = fp.user(user)
      if password is not None:
        resp = fp.pass_(password)

      logger.debug('No error: %s' % resp)
      self.reset()

    except pop_error as e:
      logger.debug('pop_error: %s' % e)
      resp = str(e)

    if persistent == '0':
      self.reset()

    code, mesg = resp.split(' ', 1)
    return self.Response(code, mesg)

class POP_passd:
  '''Brute-force poppassd (http://netwinsite.com/poppassd/)'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:code=500''',
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [106]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='106', user=None, password=None, timeout='10'):
    fp = LineReceiver()
    resp = fp.connect(host, int(port), int(timeout))
    trace = resp + '\r\n'

    try:
      if user is not None:
        cmd = 'USER %s' % user
        resp = fp.sendcmd(cmd)
        trace += '%s\r\n%s\r\n' % (cmd, resp)

      if password is not None:
        cmd = 'PASS %s' % password
        resp = fp.sendcmd(cmd)
        trace += '%s\r\n%s\r\n' % (cmd, resp)

    except LineReceiver_Error as e:
      resp = str(e)
      logger.debug('LineReceiver_Error: %s' % resp)
      trace += '%s\r\n%s\r\n' % (cmd, resp)

    finally:
      fp.close()

    code, mesg = fp.parse(resp)
    return self.Response(code, mesg, trace)

# }}}

# IMAP {{{
from imaplib import IMAP4, IMAP4_SSL
class IMAP_login:
  '''Brute-force IMAP4'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt''',
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [143]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('ssl', 'use SSL [0|1]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='', ssl='0', user=None, password=None):
    if ssl == '0':
      if not port: port = 143
      fp = IMAP4(host, port)
    else:
      if not port: port = 993
      fp = IMAP4_SSL(host, port)

    code, resp = 0, fp.welcome

    try:
      if user is not None and password is not None:
        r = fp.login(user, password)
        resp = ', '.join(r[1])

    except IMAP4.error as e:
      logger.debug('imap_error: %s' % e)
      code, resp = 1, str(e)

    return self.Response(code, resp)

# }}}

# VMauthd {{{
from ssl import wrap_socket
class LineReceiver_Error(Exception): pass
class LineReceiver:

  def connect(self, host, port, timeout, ssl=False):
    self.sock = socket.create_connection((host, port), timeout)
    banner = self.getresp()

    if ssl:
      self.sock = wrap_socket(self.sock)

    return banner # welcome banner

  def close(self):
    self.sock.close()

  def sendcmd(self, cmd):
    self.sock.sendall(cmd + '\r\n')
    return self.getresp()

  def getresp(self):
    resp = self.sock.recv(1024)
    while not resp.endswith('\n'):
      resp += self.sock.recv(1024)

    resp = resp.rstrip()
    code, _ = self.parse(resp)

    if not code.isdigit():
      raise Exception('Unexpected response: %s' % resp)

    if code[0] not in ('1', '2', '3'):
      raise LineReceiver_Error(resp)

    return resp

  def parse(self, resp):
    i = resp.rfind('\n') + 1
    code = resp[i:i+3]
    mesg = resp[i+4:]

    return code, mesg

class VMauthd_login(TCP_Cache):
  '''Brute-force VMware Authentication Daemon'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=root password=FILE0 0=passwords.txt''',
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [902]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('ssl', 'use SSL [1|0]'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, ssl, timeout):
    fp = LineReceiver()
    banner = fp.connect(host, int(port), int(timeout), ssl != '0')
    return TCP_Connection(fp, banner)

  def execute(self, host, port='902', user=None, password=None, ssl='1', timeout='10', persistent='1'):

    fp, resp = self.bind(host, port, ssl, timeout=timeout)
    trace = resp + '\r\n'

    try:
      if user is not None:
        cmd = 'USER %s' % user
        resp = fp.sendcmd(cmd)
        trace += '%s\r\n%s\r\n' % (cmd, resp)

      if password is not None:
        cmd = 'PASS %s' % password
        resp = fp.sendcmd(cmd)
        trace += '%s\r\n%s\r\n' % (cmd, resp)

    except LineReceiver_Error as e:
      resp = str(e)
      logger.debug('LineReceiver_Error: %s' % resp)
      trace += '%s\r\n%s\r\n' % (cmd, resp)

    if persistent == '0':
      self.reset()

    code, mesg = fp.parse(resp)
    return self.Response(code, mesg, trace)

# }}}

# MySQL {{{
try:
  import _mysql
except ImportError:
  warnings.append('mysql-python')

class MySQL_login:
  '''Brute-force MySQL'''

  usage_hints = (
    """%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:fgrep='Access denied for user'""",
    )
  
  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [3306]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='3306', user='anony', password='', timeout='10'):

    try:
      fp = _mysql.connect(host=host, port=int(port), user=user, passwd=password, connect_timeout=int(timeout))
      resp = '0', fp.get_server_info()

    except _mysql.Error as resp:
      logger.debug('MysqlError: %s' % resp)

    code, mesg = resp
    return self.Response(code, mesg)

# }}}

# MSSQL {{{
# I did not use pymssql because neither version 1.x nor 2.0.0b1_dev were multithreads safe (they all segfault)
class MSSQL:
  # ripped from medusa mssql.c
  hdr = '\x02\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

  pt2 = '\x30\x30\x30\x30\x30\x30\x61\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x20\x18\x81\xb8\x2c\x08\x03\x01\x06\x0a\x09\x01\x01\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x73\x71\x75\x65\x6c\x64\x61\x20\x31\x2e\x30\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

  pt3 = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x04\x02\x00\x00\x4d\x53\x44\x42\x4c\x49\x42\x00\x00\x00\x07\x06\x00\x00' \
        '\x00\x00\x0d\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
        '\x00\x00\x00\x00\x00\x00'

  langp = '\x02\x01\x00\x47\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' \
          '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
          '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x30\x30\x00\x00' \
          '\x00\x03\x00\x00\x00'

  def connect(self, host, port, timeout):
    self.fp = socket.create_connection((host, port), timeout)

  def login(self, user, password):
    MAX_LEN = 30
    user_len = len(user)
    password_len = len(password)
    data = self.hdr + user[:MAX_LEN] + '\x00' * (MAX_LEN - user_len) + chr(user_len) + \
      password[:MAX_LEN] + '\x00' * (MAX_LEN - password_len) + chr(password_len) + self.pt2 + chr(password_len) + \
      password[:MAX_LEN] + '\x00' * (MAX_LEN - password_len) + self.pt3

    self.fp.sendall(data)
    self.fp.sendall(self.langp)

    resp = self.fp.recv(1024)
    code, size = self.parse(resp)

    return code, size

  def parse(self, resp):
    i = 8
    while True:
      resp = resp[i:]
      code, size = unpack('<cH', resp[:3])
      #logger.debug('code: %s / size: %d' % (code.encode('hex'), size))

      if code == '\xfd': # Done
        break

      if code in ('\xaa', '\xab') : # Error or Info message
        num, state, severity, msg_len = unpack('IBBB', resp[3:10])
        msg = resp[11:11+msg_len]
        return num, msg

      i = size + 3
    
    raise Exception('Failed to parse response')

class MSSQL_login:
  '''Brute-force MSSQL'''

  usage_hints = (
    """%prog host=10.0.0.1 user=sa password=FILE0 0=passwords.txt -x ignore:fgrep='Login failed for user'""",
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [1433]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='1433', user='', password='', timeout='10'):
    m = MSSQL()
    m.connect(host, int(port), int(timeout))
    code, mesg = m.login(user, password)
    return self.Response(code, mesg)

# }}}

# Oracle {{{
try:
  import cx_Oracle
except ImportError:
  warnings.append('cx_Oracle')

class Oracle_login:
  '''Brute-force Oracle'''

  usage_hints = (
    """%prog host=10.0.0.1 sid=FILE0 0=sids.txt -x ignore:code=ORA-12505""",
    """%prog host=10.0.0.1 user=SYS password=FILE0 0=passwords.txt -x ignore:code=ORA-01017""",
    )
  
  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [1521]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('sid', 'sid or service names to test'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='1521', user='', password='', sid=''):
    dsn = cx_Oracle.makedsn(host, port, sid)
    try:
      fp = cx_Oracle.connect(user, password, dsn, threaded=True)
      code, mesg = '0', fp.version

    except cx_Oracle.DatabaseError as e:
      code, mesg = e.args[0].message[:-1].split(': ', 1)
      
    return self.Response(code, mesg)

# }}}

# PostgreSQL {{{
try:
  import psycopg2
except ImportError:
  warnings.append('psycopg')

class Pgsql_login:
  '''Brute-force PostgreSQL'''

  usage_hints = (
    """%prog host=10.0.0.1 user=postgres password=FILE0 0=passwords.txt -x ignore:fgrep='password authentication failed for user'""",
    )
  
  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [5432]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('database', 'databases to test [postgres]'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='5432', user=None, password=None, database='postgres', ssl='disable', timeout='10'):
    try:
      psycopg2.connect(host=host, port=int(port), user=user, password=password, database=database, sslmode=ssl, connect_timeout=int(timeout))
      code, mesg = '0', 'OK'
    except psycopg2.OperationalError as e:
      logger.debug('OperationalError: %s' % e)
      code, mesg = '1', str(e)[:-1]
  
    return self.Response(code, mesg)

# }}}

# HTTP {{{
try:
  import pycurl
except ImportError:
  warnings.append('pycurl')

class Controller_HTTP(Controller):
  def expand_key(self, arg):
    key, val = arg.split('=', 1)
    if key == 'url':
      m = re.match(r'(?:(?P<scheme>.+)://)?(?P<host>.+?)(?::(?P<port>[^/]+))?/'\
        +  '(?P<path>[^;?#]*)'\
        +  '(?:\;(?P<params>[^?#]*))?'\
        +  '(?:\?(?P<query>[^#]*))?'\
        +  '(?:\#(?P<fragment>.*))?' , val)

      if not m:
        yield (key, val)

      else:
        for k, v in m.groupdict().items():
          if v is not None:
            yield (k, v)
    else:
      yield (key, val)

class Response_HTTP(Response_Base):

  def __init__(self, code, response, trace=None, content_length=-1):
    self.content_length = content_length
    Response_Base.__init__(self, code, response, trace)

  def compact(self):
    return '%s %s' % (self.code, '%d:%d' % (self.size, self.content_length))

  def __str__(self):
    i = self.mesg.rfind('HTTP/', 0, 5000)
    if i == -1:
      return self.mesg
    else:
      j = self.mesg.find('\n', i)
      line = self.mesg[i:j]
      return line.strip()

  def match_clen(self, val):
    return match_size(self.content_length, val)

  def match_fgrep(self, val):
    return val in self.mesg

  def match_egrep(self, val):
    return re.search(val, self.mesg, re.M)

  available_conditions = Response_Base.available_conditions
  available_conditions += (
    ('clen', 'match Content-Length header (N or N-M or N- or -N)'),
    )

class HTTP_fuzz(TCP_Cache):
  '''Brute-force HTTP'''

  usage_hints = [
    """%prog url=http://10.0.0.1/FILE0 0=paths.txt -x ignore:code=404 -x ignore,retry:code=500""",

    """%prog url=http://10.0.0.1/manager/html user_pass=COMBO00:COMBO01 0=combos.txt"""
    """ -x ignore:code=401""",

    """%prog url=http://10.0.0.1/phpmyadmin/index.php method=POST"""
    """ body='pma_username=root&pma_password=FILE0&server=1&lang=en' 0=passwords.txt follow=1"""
    """ accept_cookie=1 -x ignore:fgrep='Cannot log in to the MySQL server'""",
    ]

  available_options = (
    ('url', 'main url to target (scheme://host[:port]/path?query)'),
    #('host', 'hostnames or subnets to target'),
    #('port', 'ports to target'),
    #('scheme', 'scheme [http | https]'),
    #('path', 'web path [/]'),
    #('query', 'query string'),
    ('body', 'body data'),
    ('header', 'use custom headers'),
    ('method', 'method to use [GET | POST | HEAD | ...]'),
    ('user_pass', 'username and password for HTTP authentication (user:pass)'),
    ('auth_type', 'type of HTTP authentication [basic | digest | ntlm]'),
    ('follow', 'follow any Location redirect [0|1]'),
    ('max_follow', 'redirection limit [5]'),
    ('accept_cookie', 'save received cookies to issue them in future requests [0|1]'),
    ('http_proxy', 'HTTP proxy to use (host:port)'),
    ('ssl_cert', 'client SSL certificate file (cert+key in PEM format)'),
    ('timeout_tcp', 'seconds to wait for a TCP handshake [10]'),
    ('timeout', 'seconds to wait for a HTTP response [20]'),
    ('before_urls', 'comma-separated URLs to query before the main request'),
    ('before_egrep', 'extract data from the before_urls response to place in the main request'),
    ('after_urls', 'comma-separated URLs to query after the main request'),
    ('max_mem', 'store no more than N bytes of request+response data in memory [-1 (unlimited)]'), 
    )
  available_options += TCP_Cache.available_options

  Response = Response_HTTP

  def connect(self, host, port, scheme):
    fp = pycurl.Curl()
    fp.setopt(pycurl.SSL_VERIFYPEER, 0)
    fp.setopt(pycurl.SSL_VERIFYHOST, 0)
    fp.setopt(pycurl.HEADER, 1)
    fp.setopt(pycurl.USERAGENT, 'Mozilla/5.0')
    fp.setopt(pycurl.NOSIGNAL, 1)

    return TCP_Connection(fp)

  def execute(self, url=None, host=None, port='', scheme='http', path='/', params='', query='', fragment='', body='',
    header='', method='GET', user_pass='', auth_type='basic',
    follow='0', max_follow='5', accept_cookie='0', http_proxy='', ssl_cert='', timeout_tcp='10', timeout='20', persistent='1', 
    before_urls='', before_egrep='', after_urls='', max_mem='-1'):
    
    if url:
      scheme, host, path, params, query, fragment = urlparse(url)
      if ':' in host:
        host, port = host.split(':')
      del url

    fp, _ = self.bind(host, port, scheme)

    fp.setopt(pycurl.FOLLOWLOCATION, int(follow))
    fp.setopt(pycurl.MAXREDIRS, int(max_follow))
    fp.setopt(pycurl.CONNECTTIMEOUT, int(timeout_tcp))
    fp.setopt(pycurl.TIMEOUT, int(timeout))
    fp.setopt(pycurl.PROXY, http_proxy)

    def noop(buf): pass
    fp.setopt(pycurl.WRITEFUNCTION, noop)

    def debug_func(t, s):
      if max_mem > 0 and trace.tell() > max_mem:
        return 0

      if t in (pycurl.INFOTYPE_HEADER_OUT, pycurl.INFOTYPE_DATA_OUT):
        trace.write(s)

      elif t in (pycurl.INFOTYPE_HEADER_IN, pycurl.INFOTYPE_DATA_IN):
        trace.write(s)
        response.write(s)
        
    max_mem = int(max_mem)
    response, trace = StringIO(), StringIO()

    fp.setopt(pycurl.DEBUGFUNCTION, debug_func)
    fp.setopt(pycurl.VERBOSE, 1)

    if user_pass:
      fp.setopt(pycurl.USERPWD, user_pass)
      if auth_type == 'basic':
        fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
      elif auth_type == 'digest':
        fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
      elif auth_type == 'ntlm':
        fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
      else:
        raise NotImplementedError("Incorrect auth_type '%s'" % auth_type)
    
    if ssl_cert:
      fp.setopt(pycurl.SSLCERT, ssl_cert)

    if accept_cookie == '1':
      fp.setopt(pycurl.COOKIEFILE, '') 
      # warning: do not pass a Cookie: header into HTTPHEADER if using COOKIEFILE as it will 
      # produce requests with more than one Cookie: header
      # and the server will process only one of them (eg. Apache only reads the last one)

    def perform_fp(fp, method, url, header='', body=''):
      #logger.debug('perform: %s' % url)
      fp.setopt(pycurl.URL, url) 

      if method == 'GET':
        fp.setopt(pycurl.HTTPGET, 1)

      elif method == 'POST':
        fp.setopt(pycurl.POST, 1)
        fp.setopt(pycurl.POSTFIELDS, body)

      elif method == 'HEAD':
        fp.setopt(pycurl.NOBODY, 1)

      else:
        fp.setopt(pycurl.CUSTOMREQUEST, method)

      headers = [h.strip('\r') for h in header.split('\n') if h]
      fp.setopt(pycurl.HTTPHEADER, headers)

      fp.perform()

    if before_urls:
      for before_url in before_urls.split(','):
        perform_fp(fp, 'GET', before_url)

      if before_egrep:
        for be in before_egrep.split('|'):
          mark, regex = be.split(':', 1)
          val = re.search(regex, response.getvalue(), re.M).group(1)

          header = header.replace(mark, val)
          query = query.replace(mark, val)
          body = body.replace(mark, val)

    path = quote(path)
    query = urlencode(parse_qsl(query, True))
    body = urlencode(parse_qsl(body, True))

    if port:
      host = '%s:%s' % (host, port)

    url = urlunparse((scheme, host, path, params, query, fragment))
    perform_fp(fp, method, url, header, body)

    if after_urls:
      for after_url in after_urls.split(','):
        perform_fp(fp, 'GET', after_url)

    http_code = fp.getinfo(pycurl.HTTP_CODE)
    content_length = fp.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD)

    if persistent == '0':
      self.reset()

    return self.Response(http_code, response.getvalue(), trace.getvalue(), content_length)

# }}}

# VNC {{{
try:
  from Crypto.Cipher import DES
except ImportError:
  warnings.append('pycrypto')

class VNC_Error(Exception): pass
class VNC:
  def connect(self, host, port, timeout):
    self.fp = socket.create_connection((host, port), timeout=timeout)
    resp = self.fp.recv(99) # banner

    logger.debug('banner: %s' % repr(resp))
    self.version = resp[:11].decode('ascii')

    if len(resp) > 12:
      raise VNC_Error('%s %s' % (self.version, resp[12:].decode('ascii', 'ignore')))

    return self.version

  def login(self, password):
    logger.debug('Remote version: %s' % self.version)
    major, minor = self.version[6], self.version[10]

    if (major, minor) in [('3', '8'), ('4', '1')]:
      proto = b'RFB 003.008\n'

    elif (major, minor) == ('3', '7'):
      proto = b'RFB 003.007\n'

    else:
      proto = b'RFB 003.003\n'

    logger.debug('Client version: %s' % proto[:-1])
    self.fp.sendall(proto)

    sleep(0.5)

    resp = self.fp.recv(99)
    logger.debug('Security types supported: %s' % repr(resp))

    if minor in ('7', '8'):
      code = ord(resp[0:1])
      if code == 0:
        raise VNC_Error('Session setup failed: %s' % resp.decode('ascii', 'ignore'))

      self.fp.sendall(b'\x02') # always use classic VNC authentication
      resp = self.fp.recv(99)

    else: # minor == '3':
      code = ord(resp[3:4])
      if code != 2:
        raise VNC_Error('Session setup failed: %s' % resp.decode('ascii', 'ignore'))

      resp = resp[-16:]

    if len(resp) != 16:
      raise VNC_Error('Unexpected challenge size (No authentication required? Unsupported authentication type?)')

    logger.debug('challenge: %s' % repr(resp))
    pw = password.ljust(8, '\x00')[:8] # make sure it is 8 chars long, zero padded

    key = self.gen_key(pw)
    logger.debug('key: %s' % repr(key))

    des = DES.new(key, DES.MODE_ECB)
    enc = des.encrypt(resp)

    logger.debug('enc: %s' % repr(enc))
    self.fp.sendall(enc)

    resp = self.fp.recv(99)
    logger.debug('resp: %s' % repr(resp))

    code = ord(resp[3:4])
    mesg = resp[8:].decode('ascii', 'ignore')

    if code == 1:
      return code, mesg or 'Authentication failure'

    elif code == 0:
      return code, mesg or 'OK'

    else:
      raise VNC_Error('Unknown response: %s (code: %s)' % (repr(resp), code))
         

  def gen_key(self, key):
    newkey = []
    for ki in range(len(key)):
      bsrc = ord(key[ki])
      btgt = 0
      for i in range(8):
        if bsrc & (1 << i):
          btgt = btgt | (1 << 7-i)
      newkey.append(btgt)

    if version_info[0] == 2:
      return ''.join(chr(c) for c in newkey)
    else:
      return bytes(newkey)


class VNC_login:
  '''Brute-force VNC'''

  usage_hints = (
    """%prog host=10.0.0.1 password=FILE0 0=passwords.txt -t 1 -x retry:fgrep!='Authentication failure' --max-retries -1 -x quit:code=0""",
    )
  
  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [5900]'),
    ('password', 'passwords to test'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port=None, password=None, timeout='10'):
    v = VNC()

    try:
      code, mesg = 0, v.connect(host, int(port or 5900), int(timeout))

      if password is not None:
        code, mesg = v.login(password)

    except VNC_Error as e:
      logger.debug('VNC_Error: %s' % e)
      code, mesg = 2, str(e)

    return self.Response(code, mesg)

# }}}

# DNS {{{

try:
  import dns.rdatatype
  import dns.message
  import dns.query
  import dns.reversename
except ImportError:
  warnings.append('dnspython')

def dns_query(server, timeout, protocol, qname, qtype, qclass):
  request = dns.message.make_query(qname, qtype, qclass)

  if protocol == 'tcp':
    response = dns.query.tcp(request, server, timeout=timeout, one_rr_per_rrset=True)

  else:
    response = dns.query.udp(request, server, timeout=timeout, one_rr_per_rrset=True)

    if response.flags & dns.flags.TC:
      response = dns.query.tcp(request, server, timeout=timeout, one_rr_per_rrset=True)

  return response

def generate_tld():
  gtld = [
    'aero', 'arpa', 'asia', 'biz', 'cat', 'com', 'coop', 'edu',
    'gov', 'info', 'int', 'jobs', 'mil', 'mobi', 'museum', 'name',
    'net', 'org', 'pro', 'tel', 'travel']

  cctld = [''.join(i) for i in product(*[ascii_lowercase]*2)]
  tld = gtld + cctld
  return tld, len(tld)

def generate_srv():
  common = [
    '_gc._tcp', '_kerberos._tcp', '_kerberos._udp', '_ldap._tcp',
    '_test._tcp', '_sips._tcp', '_sip._udp', '_sip._tcp', '_aix._tcp', '_aix._udp',
    '_finger._tcp', '_ftp._tcp', '_http._tcp', '_nntp._tcp', '_telnet._tcp',
    '_whois._tcp', '_h323cs._tcp', '_h323cs._udp', '_h323be._tcp', '_h323be._udp',
    '_h323ls._tcp', '_h323ls._udp', '_sipinternal._tcp', '_sipinternaltls._tcp',
    '_sip._tls', '_sipfederationtls._tcp', '_jabber._tcp', '_xmpp-server._tcp', '_xmpp-client._tcp',
    '_imap.tcp', '_certificates._tcp', '_crls._tcp', '_pgpkeys._tcp', '_pgprevokations._tcp',
    '_cmp._tcp', '_svcp._tcp', '_crl._tcp', '_ocsp._tcp', '_PKIXREP._tcp',
    '_smtp._tcp', '_hkp._tcp', '_hkps._tcp', '_jabber._udp', '_xmpp-server._udp',
    '_xmpp-client._udp', '_jabber-client._tcp', '_jabber-client._udp',
    '_adsp._domainkey', '_policy._domainkey', '_domainkey', '_ldap._tcp.dc._msdcs', '_ldap._udp.dc._msdcs']

  def distro():
    import os
    import re
    files = ['/usr/share/nmap/nmap-protocols', '/usr/share/nmap/nmap-services', '/etc/protocols', '/etc/services']
    ret = []
    for f in files:
      if not os.path.isfile(f):
        logger.warn("File '%s' is missing, there will be less records to test" % f)
        continue
      for line in open(f):
        match = re.match(r'([a-zA-Z0-9]+)\s', line)
        if not match: continue
        for w in re.split(r'[^a-z0-9]', match.group(1).strip().lower()):
          ret.extend(['_%s.%s' % (w, i) for i in ('_tcp', '_udp')])
    return ret

  srv = set(common + distro())
  return srv, len(srv)

class HostInfo:
  def __init__(self):
    self.name = set()
    self.ip = set()
    self.alias = set()

  def __str__(self):
    line = ''
    if self.name:
      line = ' '.join(self.name)
    if self.ip:
      if line: line += ' / '
      line += ' '.join(map(str, self.ip))
    if self.alias:
      if line: line += ' / '
      line += ' '.join(self.alias)

    return line

class Controller_DNS(Controller):
  records = defaultdict(list)
  hostmap = defaultdict(HostInfo)

  # show_final {{{
  def show_final(self):
    ''' Expected output:
    Records -----
          ftp.example.com.   IN A       10.0.1.1
          www.example.com.   IN A       10.0.1.1
         prod.example.com.   IN CNAME   www.example.com.
         ipv6.example.com.   IN AAAA    dead:beef::
          dev.example.com.   IN A       10.0.1.2
          svn.example.com.   IN A       10.0.2.1
      websrv1.example.com.   IN CNAME   prod.example.com.
         blog.example.com.   IN CNAME   example.wordpress.com.
    '''
    print('Records ' + '-'*42)
    for name, infos in sorted(self.records.items()):
      for qclass, qtype, rdata in infos:
        print('%34s %4s %-7s %s' % (name, qclass, qtype, rdata))

    ''' Expected output:
    Hostmap ------
           ipv6.example.com dead:beef::
            ftp.example.com 10.0.1.1
            www.example.com 10.0.1.1
           prod.example.com
        websrv1.example.com
            dev.example.com 10.0.1.2
            svn.example.com 10.0.2.1
      example.wordpress.com ?
           blog.example.com
    Domains ---------------------------
                example.com 8
    Networks --------------------------
                           dead:beef::
                              10.0.1.x
                              10.0.2.1
    '''
    ipmap = defaultdict(HostInfo)
    noips = defaultdict(list)

    '''
    hostmap = {
       'www.example.com': {'ip': ['10.0.1.1'], 'alias': ['prod.example.com']},
       'ftp.example.com': {'ip': ['10.0.1.1'], 'alias': []},
       'prod.example.com': {'ip': [], 'alias': ['websrv1.example.com']},
       'ipv6.example.com': {'ip': ['dead:beef::'], 'alias': []},
       'dev.example.com': {'ip': ['10.0.1.2'], 'alias': []},
       'example.wordpress.com': {'ip': [], 'alias': ['blog.example.com']},

    ipmap = {'10.0.1.1': {'name': ['www.example.com', 'ftp.example.com'], 'alias': ['prod.example.com', 'websrv1.example.com']}, ...
    noips = {'example.wordpress.com': ['blog.example.com'],
    '''

    for name, hinfo in self.hostmap.items(): 
      for ip in hinfo.ip:
        ip = IP(ip)
        ipmap[ip].name.add(name)
        ipmap[ip].alias.update(hinfo.alias)

    for name, hinfo in self.hostmap.items():
      if not hinfo.ip and hinfo.alias:
        found = False
        for ip, v in ipmap.items():
          if name in v.alias:
            for alias in hinfo.alias:
              ipmap[ip].alias.add(alias)
              found = True

        if not found: # orphan CNAME hostnames (with no IP address) may be still valid virtual hosts
          noips[name].extend(hinfo.alias)

    print('Hostmap ' + '-'*42)
    for ip, hinfo in sorted(ipmap.items()):
      for name in hinfo.name:
        print('%34s %s' % (name, ip))
      for alias in hinfo.alias:
        print('%34s' % alias)

    for k, v in noips.items():
      print('%34s ?' % k)
      for alias in v:
        print('%34s' % alias)

    print('Domains ' + '-'*42)
    domains = {}
    for ip, hinfo in ipmap.items():
      for name in hinfo.name.union(hinfo.alias):
        if name.count('.') > 1:
          i = 1
        else:
          i = 0
        d = '.'.join(name.split('.')[i:])
        if d not in domains: domains[d] = 0
        domains[d] += 1

    for domain, count in sorted(domains.items(), key=lambda a:a[0].split('.')[-1::-1]):
      print('%34s %d' % (domain, count))

    print('Networks ' + '-'*41)
    nets = {}
    for ip in set(ipmap):
      if not ip.version() == 4:
        nets[ip] = [ip]
      else:
        n = ip.make_net('255.255.255.0')
        if n not in nets: nets[n] = []
        nets[n].append(ip)

    for net, ips in sorted(nets.items()):
      if len(ips) == 1:
        print(' '*34 + ' %s' % ips[0])
      else:
        print(' '*34 + ' %s.x' % '.'.join(str(net).split('.')[:-1]))

  # }}}

  def push_final(self, resp):
    if hasattr(resp, 'rrs'):
      for rr in resp.rrs:
        name, qclass, qtype, data = rr

        info = (qclass, qtype, data)
        if info not in self.records[name]:
          self.records[name].append(info)

        if not qclass == 'IN':
          continue

        if qtype == 'PTR':
          data = data[:-1]
          self.hostmap[data].ip.add(name)

        else:
          if qtype in ('A', 'AAAA'):
            name = name[:-1]
            self.hostmap[name].ip.add(data)

          elif qtype == 'CNAME':
            name, data = name[:-1], data[:-1]
            self.hostmap[data].alias.add(name)


class DNS_reverse:
  '''Reverse lookup subnets'''

  usage_hints = [
    """%prog host=NET0 0=192.168.0.0/24 -x ignore:code=3""",
    """%prog host=NET0 0=216.239.32.0-216.239.47.255,8.8.8.0/24 -x ignore:code=3 -x ignore:fgrep!=google.com -x ignore:fgrep=216-239-""",
    ]

  available_options = (
    ('host', 'IP addresses to reverse lookup'),
    ('server', 'name server to query (directly asking a zone authoritative NS may return more results) [8.8.8.8]'),
    ('timeout', 'seconds to wait for a response [5]'),
    ('protocol', 'send queries over udp or tcp [udp]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, server='8.8.8.8', timeout='5', protocol='udp'):

    response = dns_query(server, int(timeout), protocol, dns.reversename.from_address(host), qtype='PTR', qclass='IN')

    code = response.rcode()
    status = dns.rcode.to_text(code)
    rrs = [[host, c, t, d] for _, _, c, t, d in [rr.to_text().split(' ', 4) for rr in response.answer]]

    mesg = '%s %s' % (status, ''.join('[%s]' % ' '.join(rr) for rr in rrs))
    resp = self.Response(code, mesg)

    resp.rrs = rrs

    return resp

class DNS_forward:
  '''Forward lookup names'''

  usage_hints = [
    """%prog name=FILE0.google.com 0=names.txt -x ignore:code=3""",
    """%prog name=google.MOD0 0=TLD -x ignore:code=3""",
    """%prog name=MOD0.microsoft.com 0=SRV qtype=SRV -x ignore:code=3""",
    ]

  available_options = (
    ('name', 'domain names to lookup'),
    ('server', 'name server to query (directly asking the zone authoritative NS may return more results) [8.8.8.8]'),
    ('timeout', 'seconds to wait for a response [5]'),
    ('protocol', 'send queries over udp or tcp [udp]'),
    ('qtype', 'type to query [ANY]'),
    ('qclass', 'class to query [IN]'),
    )
  available_actions = ()

  available_keys = {
    'TLD': generate_tld,
    'SRV': generate_srv,
    }

  Response = Response_Base  

  def execute(self, name, server='8.8.8.8', timeout='5', protocol='udp', qtype='ANY', qclass='IN'):
    
    response = dns_query(server, int(timeout), protocol, name, qtype=qtype, qclass=qclass)

    code = response.rcode()
    status = dns.rcode.to_text(code)
    rrs = [[n, c, t, d] for n, _, c, t, d in [rr.to_text().split(' ', 4) for rr in response.answer + response.additional + response.authority]]

    mesg = '%s %s' % (status, ''.join('[%s]' % ' '.join(rr) for rr in rrs))
    resp = self.Response(code, mesg)

    resp.rrs = rrs

    return resp

# }}}

# SNMP {{{
try:
  from pysnmp.entity.rfc3413.oneliner import cmdgen
except ImportError:
  warnings.append('pysnmp')

class SNMP_login:
  '''Brute-force SNMP v1/2/3'''

  usage_hints = (
    """%prog host=10.0.0.1 version=2 community=FILE0 1=names.txt -x ignore:mesg='No SNMP response received before timeout'""",
    """%prog host=10.0.0.1 version=3 user=FILE0 0=logins.txt -x ignore:mesg=unknownUserName""",
    """%prog host=10.0.0.1 version=3 user=myuser auth_key=FILE0 0=passwords.txt -x ignore:mesg=wrongDigest""",
    )
  
  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [161]'),
    ('version', 'SNMP version to use [2|3|1]'),
    #('security_name', 'SNMP v1/v2 username, for most purposes it can be any arbitrary string [test-agent]'),
    ('community', 'SNMPv1/2c community names to test [public]'),
    ('user', 'SNMPv3 usernames to test [myuser]'),
    ('auth_key', 'SNMPv3 pass-phrases to test [my_password]'),
    #('priv_key', 'SNMP v3 secret key for encryption'), # see http://pysnmp.sourceforge.net/docs/4.x/index.html#UsmUserData
    #('auth_protocol', ''),
    #('priv_protocol', ''),
    ('timeout', 'seconds to wait for a response [1]'),
    ('retries', 'number of successive request retries [2]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port=None, version='2', community='public', user='myuser', auth_key='my_password', timeout='1', retries='2'):
    if version in ('1', '2'):
      security_model = cmdgen.CommunityData('test-agent', community, 0 if version == '1' else 1)

    elif version == '3':
      security_model = cmdgen.UsmUserData(user, auth_key) # , priv_key)
      if len(auth_key) < 8:
        return self.Response('1', 'SNMPv3 requires passphrases to be at least 8 characters long')

    else:
      raise NotImplementedError("Incorrect SNMP version '%s'" % version)

    errorIndication, errorStatus, errorIndex, varBinds = cmdgen.CommandGenerator().getCmd(
      security_model,
      cmdgen.UdpTransportTarget((host, int(port or 161)), timeout=int(timeout), retries=int(retries)),
      (1,3,6,1,2,1,1,1,0)
      )

    code = '%d-%d' % (errorStatus, errorIndex)
    if not errorIndication:
      mesg = '%s' % varBinds
    else:
      mesg = '%s' % errorIndication 

    return self.Response(code, mesg)

# }}}

# Unzip {{{
if not which('unzip'):
  warnings.append('unzip')

class Unzip_pass:
  '''Brute-force the password of encrypted ZIP files'''

  usage_hints = [
    """%prog zipfile=path/to/file.zip password=FILE0 0=passwords.txt -x ignore:code!=0""",
    ]

  available_options = (
    ('zipfile', 'ZIP files to test'),
    ('password', 'passwords to test'),
    )

  available_actions = ()

  Response = Response_Base

  def execute(self, zipfile, password):
    zipfile = os.path.abspath(zipfile)
    cmd = ['unzip', '-t', '-q', '-P', password, zipfile]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = p.stdout.read()
    err = p.stderr.read()

    code = p.wait()
    mesg = repr(out.strip())[1:-1]
    trace = '[out]\n%s\n[err]\n%s' % (out, err)

    return self.Response(code, mesg, trace)
      
# }}}

# Keystore {{{
if not which('keytool'):
  warnings.append('java')

class Keystore_pass:
  '''Brute-force the password of Java keystore files'''

  usage_hints = [
    """%prog keystore=path/to/keystore.jks password=FILE0 0=passwords.txt -x ignore:fgrep='password was incorrect'""",
    ]

  available_options = (
    ('keystore', 'keystore files to test'),
    ('password', 'passwords to test'),
    ('storetype', 'type of keystore to test'),
    )

  available_actions = ()

  Response = Response_Base

  def execute(self, keystore, password, storetype='jks'):
    keystore = os.path.abspath(keystore)
    cmd = ['keytool', '-list', '-keystore', keystore, '-storepass', password, '-storetype', storetype]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = p.stdout.read()
    err = p.stderr.read()

    code = p.wait()
    mesg = repr(out.strip())[1:-1]
    trace = '[out]\n%s\n[err]\n%s' % (out, err)

    return self.Response(code, mesg, trace)

# }}}

# modules {{{
modules = [
  ('ftp_login', (Controller, FTP_login)),
  ('ssh_login', (Controller, SSH_login)),
  ('telnet_login', (Controller, Telnet_login)),
  ('smtp_login', (Controller, SMTP_login)),
  ('smtp_vrfy', (Controller, SMTP_vrfy)),
  ('smtp_rcpt', (Controller, SMTP_rcpt)),
  ('finger_lookup', (Controller_Finger, Finger_lookup)),
  ('http_fuzz', (Controller_HTTP, HTTP_fuzz)),
  ('pop_login', (Controller, POP_login)),
  ('pop_passd', (Controller, POP_passd)),
  ('imap_login', (Controller, IMAP_login)),
  ('ldap_login', (Controller, LDAP_login)),
  ('smb_login', (Controller, SMB_login)),
  ('smb_lookupsid', (Controller, SMB_lookupsid)),
  ('vmauthd_login', (Controller, VMauthd_login)),
  ('mssql_login', (Controller, MSSQL_login)),
  ('oracle_login', (Controller, Oracle_login)),
  ('mysql_login', (Controller, MySQL_login)),
  #'rdp_login', 
  ('pgsql_login', (Controller, Pgsql_login)),
  ('vnc_login', (Controller, VNC_login)),

  ('dns_forward', (Controller_DNS, DNS_forward)),
  ('dns_reverse', (Controller_DNS, DNS_reverse)),
  ('snmp_login', (Controller, SNMP_login)),
  
  ('unzip_pass', (Controller, Unzip_pass)),
  ('keystore_pass', (Controller, Keystore_pass)),
  ]

dependencies = {
  'paramiko': [('ssh_login',), 'http://www.lag.net/paramiko/', '1.7.7.1'],
  'pycurl': [('http_fuzz',), 'http://pycurl.sourceforge.net/', '7.19.0'],
  'openldap': [('ldap_login',), 'http://www.openldap.org/', '2.4.24'],
  'impacket': [('smb_login','smb_lookupsid'), 'http://oss.coresecurity.com/projects/impacket.html', 'svn#414'],
  'cx_Oracle': [('oracle_login',), 'http://cx-oracle.sourceforge.net/', '5.1.1'],
  'mysql-python': [('mysql_login',), 'http://sourceforge.net/projects/mysql-python/', '1.2.3'],
  'psycopg': [('pgsql_login',), 'http://initd.org/psycopg/', '2.4.5'],
  'pycrypto': [('vnc_login',), 'http://www.dlitz.net/software/pycrypto/', '2.3'],
  'dnspython': [('dns_reverse', 'dns_forward'), 'http://www.dnspython.org/', '1.10.0'],
  'IPy': [('dns_reverse', 'dns_forward'), 'https://github.com/haypo/python-ipy', '0.75'],
  'pysnmp': [('snmp_login',), 'http://pysnmp.sf.net/', '4.2.1'],
  'unzip': [('unzip_pass',), 'http://www.info-zip.org/', '6.0'],
  'java': [('keystore_pass',), 'http://www.oracle.com/technetwork/java/javase/', '6'],
  'python': [('ftp_login',), 'http://www.python.org/', '2.7'],
  }
# }}}

# main {{{
if __name__ == '__main__':
  from sys import argv
  from os.path import basename

  def show_usage():
    print(__banner__)
    print('''Usage: patator.py module --help

Available modules:
%s''' % '\n'.join('  + %-13s : %s' % (k, v[1].__doc__) for k, v in modules))

    exit(2)

  available = dict(modules)
  name = basename(argv[0]).lower()

  if name not in available:
    if len(argv) == 1:
      show_usage()

    name = basename(argv[1]).lower()
    if name not in available:
      show_usage()

    argv = argv[1:]

  # dependencies
  abort = False
  for w in warnings:
    mods, url, ver = dependencies[w]
    if name in mods:
      print('ERROR: %s %s (%s) is required to run %s.' % (w, ver, url, name))
      abort = True

  if abort:
    print('Please read the README inside for more information.')
    exit(3)

  # start
  ctrl, module = available[name]
  powder = ctrl(module, [name] + argv[1:])
  powder.fire()

# }}}

# vim: ts=2 sw=2 sts=2 et fdm=marker bg=dark
