#!/usr/bin/env python3

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

import sys

__author__  = 'Sebastien Macke'
__email__   = 'patator@hsc.fr'
__url__     = 'http://www.hsc.fr/ressources/outils/patator/'
__git__     = 'https://github.com/lanjelot/patator'
__twitter__ = 'https://twitter.com/lanjelot'
__version__ = '0.9'
__license__ = 'GPLv2'
__pyver__   = '%d.%d.%d' % sys.version_info[0:3]
__banner__  = 'Patator %s (%s) with python-%s' % (__version__, __git__, __pyver__)

# README {{{
'''
INTRODUCTION
------------

* What ?

Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.

Currently it supports the following modules:
  + ftp_login      : Brute-force FTP
  + ssh_login      : Brute-force SSH
  + telnet_login   : Brute-force Telnet
  + smtp_login     : Brute-force SMTP
  + smtp_vrfy      : Enumerate valid users using SMTP VRFY
  + smtp_rcpt      : Enumerate valid users using SMTP RCPT TO
  + finger_lookup  : Enumerate valid users using Finger
  + http_fuzz      : Brute-force HTTP
  + rdp_gateway    : Brute-force RDP Gateway
  + ajp_fuzz       : Brute-force AJP
  + pop_login      : Brute-force POP3
  + pop_passd      : Brute-force poppassd (http://netwinsite.com/poppassd/)
  + imap_login     : Brute-force IMAP4
  + ldap_login     : Brute-force LDAP
  + dcom_login     : Brute-force DCOM
  + smb_login      : Brute-force SMB
  + smb_lookupsid  : Brute-force SMB SID-lookup
  + rlogin_login   : Brute-force rlogin
  + vmauthd_login  : Brute-force VMware Authentication Daemon
  + mssql_login    : Brute-force MSSQL
  + oracle_login   : Brute-force Oracle
  + mysql_login    : Brute-force MySQL
  + mysql_query    : Brute-force MySQL queries
  * rdp_login      : Brute-force RDP (NLA)
  + pgsql_login    : Brute-force PostgreSQL
  + vnc_login      : Brute-force VNC

  + dns_forward    : Forward DNS lookup
  + dns_reverse    : Reverse DNS lookup
  + snmp_login     : Brute-force SNMP v1/2/3
  + ike_enum       : Enumerate IKE transforms

  + unzip_pass     : Brute-force the password of encrypted ZIP files
  + keystore_pass  : Brute-force the password of Java keystore files
  + sqlcipher_pass : Brute-force the password of SQLCipher-encrypted databases
  + umbraco_crack  : Crack Umbraco HMAC-SHA1 password hashes

  + tcp_fuzz       : Fuzz TCP services
  + dummy_test     : Testing module

Future modules to be implemented:
  - rdp_login w/no NLA

The name "Patator" comes from https://www.youtube.com/watch?v=9sF9fTALhVA

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
      + show progress during execution (press Enter)
      + pause/unpause execution (press p)
      + increase/decrease verbosity
      + add new actions & conditions during runtime (eg. to exclude more types of response from showing)
      + ... press h to see all available interactive commands

  * Use persistent connections (ie. will test several passwords until the server disconnects)

  * Multi-threaded

  * Flexible user input
    - Any module parameter can be fuzzed:
      + use the FILE keyword to iterate over a file
      + use the COMBO keyword to iterate over a combo file
      + use the NET keyword to iterate over every hosts of a network subnet
      + use the RANGE keyword to iterate over hexadecimal, decimal or alphabetical ranges
      + use the PROG keyword to iterate over the output of an external program

    - Iteration over the joined wordlists can be done in any order

  * Save every response (along with request) to seperate log files for later reviewing


INSTALL
-------

* Dependencies (best tested versions)

                 |  Required for  |                        URL                         | Version |
--------------------------------------------------------------------------------------------------
paramiko         | SSH            | http://www.lag.net/paramiko/                       |   2.7.1 |
--------------------------------------------------------------------------------------------------
pycurl           | HTTP           | http://pycurl.sourceforge.net/                     |  7.43.0 |
--------------------------------------------------------------------------------------------------
libcurl          | HTTP           | https://curl.haxx.se/                              |  7.58.0 |
--------------------------------------------------------------------------------------------------
ajpy             | AJP            | https://github.com/hypn0s/AJPy/                    |   0.0.4 |
--------------------------------------------------------------------------------------------------
openldap         | LDAP           | http://www.openldap.org/                           |  2.4.45 |
--------------------------------------------------------------------------------------------------
impacket         | SMB, MSSQL     | https://github.com/CoreSecurity/impacket           |  0.9.20 |
--------------------------------------------------------------------------------------------------
pyOpenSSL        | impacket       | https://pyopenssl.org/                             |  19.1.0 |
--------------------------------------------------------------------------------------------------
cx_Oracle        | Oracle         | http://cx-oracle.sourceforge.net/                  |   7.3.0 |
--------------------------------------------------------------------------------------------------
mysqlclient      | MySQL          | https://github.com/PyMySQL/mysqlclient-python      |   1.4.6 |
--------------------------------------------------------------------------------------------------
xfreerdp         | RDP (NLA)      | https://github.com/FreeRDP/FreeRDP/                |   1.2.0 |
--------------------------------------------------------------------------------------------------
psycopg          | PostgreSQL     | http://initd.org/psycopg/                          |   2.8.4 |
--------------------------------------------------------------------------------------------------
pycrypto         | VNC, impacket  | http://www.dlitz.net/software/pycrypto/            |   2.6.1 |
--------------------------------------------------------------------------------------------------
dnspython        | DNS            | http://www.dnspython.org/                          |  1.16.0 |
--------------------------------------------------------------------------------------------------
IPy              | NET keyword    | https://github.com/haypo/python-ipy                |     1.0 |
--------------------------------------------------------------------------------------------------
pysnmp           | SNMP           | http://pysnmp.sourceforge.net/                     |  4.4.12 |
--------------------------------------------------------------------------------------------------
pyasn1           | SNMP, impacket | http://sourceforge.net/projects/pyasn1/            |   0.4.8 |
--------------------------------------------------------------------------------------------------
ike-scan         | IKE            | http://www.nta-monitor.com/tools-resources/        |     1.9 |
--------------------------------------------------------------------------------------------------
unzip            | ZIP passwords  | http://www.info-zip.org/                           |     6.0 |
--------------------------------------------------------------------------------------------------
Java             | keystore files | http://www.oracle.com/technetwork/java/javase/     |       6 |
--------------------------------------------------------------------------------------------------
pysqlcipher3     | SQLCipher      | https://github.com/rigglemania/pysqlcipher3        |   1.0.3 |
--------------------------------------------------------------------------------------------------
python           |                | http://www.python.org/                             |     3.6 |
--------------------------------------------------------------------------------------------------

* Shortcuts (optional)
ln -s path/to/patator.py /usr/bin/ftp_login
ln -s path/to/patator.py /usr/bin/http_fuzz
etc.


USAGE
-----

$ python patator.py <module> -h # or
$ <module> -h                   # if shortcuts were created

There are global options and module options:
  - all global options start with - or --
  - all module options are of the form option=value

All module options are fuzzable:
---------
./module host=FILE0 port=FILE1 foobar=FILE2.google.FILE3 0=hosts.txt 1=ports.txt 2=foo.txt 3=bar.txt

If a module option starts with the @ character, data will be loaded from the given filename.
$ ./http_fuzz raw_request=@req.txt 0=vhosts.txt 1=uagents.txt

The keywords (FILE, COMBO, NET, ...) act as place-holders. They indicate the type of wordlist
and where to replace themselves with the actual words to test.

Each keyword is numbered in order to:
  - match the corresponding wordlist
  - and indicate in what order to iterate over all the wordlists

For example, this would be the classic order:
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

While a more effective order might be:
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

By default Patator iterates over the cartesian product of all payload sets. Use
the --groups option to iterate over sets simultaneously instead. For example to
distribute all payloads among identical servers:
---------
$ ./module name=FILE0.FILE1 resolver=FILE2 0=names.txt 1=domains.txt 2=ips.txt --groups 0,1:2
ftp.abc.fr 8.8.8.8
ftp.xyz.fr 8.8.4.4
git.abc.fr 8.8.8.8
git.xyz.fr 8.8.4.4
www.abc.fr 8.8.8.8
www.xyz.fr 8.8.4.4

The numbers of every keyword given on the command line must be specified.
Use ',' to iterate over the cartesian product of sets and use ':' to iterate
over sets simultaneously.


* Keywords

Brute-force a list of hosts with a file containing combo entries (each line => login:password).
---------
./module host=FILE0 user=COMBO10 password=COMBO11 0=hosts.txt 1=combos.txt

Scan subnets to just grab version banners.
---------
./module host=NET0 0=10.0.1.0/24,10.0.2.0/24,10.0.3.128-10.0.3.255

Fuzz a parameter by iterating over a range of values.
---------
./module param=RANGE0 0=hex:0x00-0xffff
./module param=RANGE0 0=int:0-500
./module param=RANGE0 0=lower:a-zzz

Fuzz a parameter by iterating over the output of an external program.
---------
./module param=PROG0 0='john -stdout -i'
./module param=PROG0 0='mp64.bin ?l?l?l',$(mp64.bin --combination ?l?l?l) # http://hashcat.net/wiki/doku.php?id=maskprocessor


* Actions & Conditions

Use the -x option to do specific actions upon receiving specific responses. For example:

Ignore responses with status code 200 *AND* a size within a specific range.
---------
./module host=10.0.0.1 user=FILE0 -x ignore:code=200,size=57-74

Ignore responses with status code 500 *OR* containing "Internal error".
---------
./module host=10.0.0.1 user=FILE0 -x ignore:code=500 -x ignore:fgrep='Internal error'

Remember that conditions are ANDed within the same -x option, use multiple -x options to
specify ORed conditions.


* Actions skip and free

Stop testing the same value from keyword #0 after a valid combination is found.
---------
./module data=FILE0.FILE1 -x skip=0:fgrep=Success

Stop testing the same combination after a valid match is found.
---------
./module data=FILE0.FILE1 data2=RANGE2 -x free=data:fgrep=Success

* Failures

During execution, failures may happen, such as a TCP connect timeout for
example. By definition a failure is an exception that the module does not expect,
and as a result the exception is caught upstream by the controller.

Such exceptions, or failures, are not immediately reported to the user, the
controller will retry 4 more times (see --max-retries) before reporting the
failed payload to the user with the logging level "FAIL".


* Read carefully the following examples to get a good understanding of how patator works.
{{{ FTP

* Brute-force authentication. Do not report wrong passwords.
---------
$ ftp_login host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:mesg='Login incorrect.'

NB0. If you get errors like "500 OOPS: priv_sock_get_cmd", use -x ignore,reset,retry:code=500
     in order to retry the last login/password using a new TCP connection. Odd servers like vsftpd
     return this when they shut down the TCP connection (ie. max login attempts reached).

NB1. If you get errors like "too many connections from your IP address", try decreasing the number of
     threads, the server may be enforcing a maximum number of concurrent connections.

* Same as before, but stop testing a user after his password is found.
---------
$ ftp_login ... -x free=user:code=0


* Find anonymous FTP servers on a subnet.
---------
$ ftp_login host=NET0 user=anonymous password=test@example.com 0=10.0.0.0/24

}}}
{{{ SSH
* Brute-force authentication with password same as login (aka single mode). Do not report wrong passwords.
---------
$ ssh_login host=10.0.0.1 user=FILE0 password=FILE0 0=logins.txt -x ignore:mesg='Authentication failed.'

NB. If you get errors like "Error reading SSH protocol banner ... Connection reset by peer",
    try decreasing the number of threads, the server may be enforcing a maximum
    number of concurrent connections (eg. MaxStartups in OpenSSH).


* Brute-force several hosts and stop testing a host after a valid password is found.
---------
$ ssh_login host=FILE0 user=FILE1 password=FILE2 0=hosts.txt 1=logins.txt 2=passwords.txt -x free=host:code=0


* Same as previous, but stop testing a user on a host after his password is found.
---------
$ ssh_login host=FILE0 user=FILE1 password=FILE2 0=hosts.txt 1=logins.txt 2=passwords.txt -x free=host+user:code=0

}}}
{{{ Telnet

* Brute-force authentication.
  (a) Enter login after first prompt is detected, enter password after second prompt.
  (b) The regex to detect the login and password prompts.
  (c) Reconnect when we get no login prompt back (max number of tries reached or successful login).
------------                 (a)
$ telnet_login host=10.0.0.1 inputs='FILE0\nFILE1' 0=logins.txt 1=passwords.txt \
    prompt_re='tux login:|Password:' -x reset:egrep!='Login incorrect.+tux login:'
    (b)                              (c)

NB. If you get errors like "telnet connection closed", try decreasing the number of threads,
    the server may be enforcing a maximum number of concurrent connections.

}}}
{{{ SMTP

* Enumerate valid users using the VRFY command.
  (a) Do not report invalid recipients.
  (b) Do not report when the server shuts us down with "421 too many errors", reconnect and resume testing.
---------                                         (a)
$ smtp_vrfy host=10.0.0.1 user=FILE0 0=logins.txt -x ignore:fgrep='User unknown in local recipient table' \
    -x ignore,reset,retry:code=421
    (b)

* Use the RCPT TO command in case the VRFY command is not available.
---------
$ smtp_rcpt host=10.0.0.1 user=FILE0@localhost 0=logins.txt helo='ehlo mx.fb.com' mail_from=root


* Brute-force authentication.
  (a) Send a fake hostname (by default your host fqdn is sent)
---------                  (a)
$ smtp_login host=10.0.0.1 helo='ehlo its.me.com' user=FILE0@dom.com password=FILE1 0=logins.txt 1=passwords.txt

}}}
{{{ HTTP

* Find hidden web resources.
  (a) Use a specific header.
  (b) Follow redirects.
  (c) Do not report 404 errors.
  (d) Retry on 500 errors.
---------                                          (a)
$ http_fuzz url=http://localhost/FILE0 0=words.txt header='Cookie: SESSID=A2FD8B2DA4' \
    follow=1 -x ignore:code=404 -x ignore,retry:code=500
    (b)      (c)                (d)

NB. You may be able to go 10 times faster using webef (http://www.hsc.fr/ressources/outils/webef/).
    It is the fastest HTTP brute-forcer I know, yet at the moment it still lacks useful features
    that will prevent you from performing the following attacks.

* Brute-force phpMyAdmin logon.
  (a) Use POST requests.
  (b) Follow redirects using cookies sent by server.
  (c) Ignore failed authentications.
---------                                            (a)         (b)      (b)
$ http_fuzz url=http://10.0.0.1/phpmyadmin/index.php method=POST follow=1 accept_cookie=1 \
    body='pma_username=root&pma_password=FILE0&server=1&lang=en' 0=passwords.txt \
    -x ignore:fgrep='Cannot log in to the MySQL server'
    (c)

* Scan subnet for directory listings.
  (a) Ignore not matching reponses.
  (b) Save matching responses into directory.
---------
$ http_fuzz url=http://NET0/FILE1 0=10.0.0.0/24 1=dirs.txt -x ignore:fgrep!='Index of' \
    -l /tmp/directory-listings                             (a)
    (b)

* Brute-force Basic authentication.
  (a) Single mode (login == password).
  (b) Do not report failed login attempts.
---------
$ http_fuzz url=http://10.0.0.1/manager/html user_pass=FILE0:FILE0 0=logins.txt -x ignore:code=401
                                             (a)                                (b)

* Find hidden virtual hosts.
  (a) Read template from file.
  (b) Fuzz both the Host and User-Agent headers.
  (c) Stop testing a virtual host name after a valid one is found.
---------
$ echo -e 'Host: FILE0\nUser-Agent: FILE1' > headers.txt
$ http_fuzz url=http://10.0.0.1/ header=@headers.txt 0=vhosts.txt 1=agents.txt -x skip=0:code!=404
                                 (a)                (b)                           (c)

* Brute-force logon using GET requests.
  (a) Encode everything surrounded by the two tags _@@_ in hexadecimal.
  (b) Ignore HTTP 200 responses with a content size (header+body) within given range
      and that also contain the given string.
  (c) Use a different delimiter string because the comma cannot be escaped.
---------                                                                     (a)
$ http_fuzz url='http://10.0.0.1/login?username=admin&password=_@@_FILE0_@@_' -e _@@_:hex \
    0=words.txt -x ignore:'code=200|size=1500-|fgrep=Welcome, unauthenticated user' -X '|'
                (b)                                                                 (c)

* Brute-force logon that enforces two random nonces to be submitted along every POST.
  (a) First, request the page that provides the nonces as hidden input fields.
  (b) Use regular expressions to extract the nonces that are to be submitted along the main request.
---------
$ http_fuzz url=http://10.0.0.1/login method=POST body='user=admin&pass=FILE0&nonce1=_N1_&nonce2=_N2_' 0=passwords.txt accept_cookie=1 \
 before_urls=http://10.0.0.1/index before_egrep='_N1_:<input type="hidden" name="nonce1" value="(\w+)"|_N2_:name="nonce2" value="(\w+)"'
 (a)                               (b)

* Test the OPTIONS method against a list of URLs.
  (a) Ignore URLs that only allow the HEAD and GET methods.
  (b) Header end of line is '\r\n'.
  (c) Use a different delimiter string because the comma cannot be escaped.
---------
$ http_fuzz url=FILE0 0=urls.txt method=OPTIONS -x ignore:egrep='^Allow: HEAD, GET\r$' -X '|'
                                                (a)                               (b)  (c)
}}}
{{{ LDAP

* Brute-force authentication.
  (a) Do not report wrong passwords.
  (b) Talk SSL/TLS to port 636.
---------
$ ldap_login host=10.0.0.1 binddn='cn=FILE0,dc=example,dc=com' 0=logins.txt bindpw=FILE1 1=passwords.txt \
    -x ignore:mesg='ldap_bind: Invalid credentials (49)' ssl=1 port=636
    (a)                                                  (b)
}}}
{{{ SMB

* Brute-force authentication.
---------
$ smb_login host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:fgrep=STATUS_LOGON_FAILURE

NB. If you suddenly get STATUS_ACCOUNT_LOCKED_OUT errors for an account although
    it is not the first password you test on this account, then you must have locked it.

* Pass-the-hash.
  (a) Test a list of hosts.
  (b) Test every user (each line := login:rid:LM hash:NT hash).
---------
$ smb_login host=FILE0 0=hosts.txt user=COMBO10 password_hash=COMBO12:COMBO13 1=pwdump.txt -x ...
            (a)                                 (b)
}}}
{{{ rlogin

* Brute-force usernames that root might be allowed to login as with no password (eg. a ~/.rhosts file with the line "+ root").
$ rlogin_login host=10.0.0.1 luser=root user=FILE0 0=logins.txt persistent=0 -x ignore:fgrep=Password:

* Brute-force usernames that might be allowed to login as root with no password (eg. a /root/.rhosts file with the line "+ john").
$ rlogin_login host=10.0.0.1 user=root luser=FILE0 0=logins.txt persistent=0 -x ignore:fgrep=Password:

}}}
{{{ MSSQL

* Brute-force authentication.
-----------
$ mssql_login host=10.0.0.1 user=sa password=FILE0 0=passwords.txt -x ignore:fgrep='Login failed for user'

}}}
{{{ Oracle
Beware, by default in Oracle, accounts are permanently locked out after 10 wrong passwords,
except for the SYS account.

* Brute-force authentication.
------------
$ oracle_login host=10.0.0.1 user=SYS password=FILE0 0=passwords.txt sid=ORCL -x ignore:code=ORA-01017

NB0. With Oracle 10g XE (Express Edition), you do not need to pass a SID.

NB1. If you get ORA-12516 errors, it may be because you reached the limit of
     concurrent connections or db processes, try using "--rate-limit 0.5 -t 2" to be
     more polite. Also you can run "alter system set processes=150 scope=spfile;"
     and restart your database to get rid of this.

* Brute-force SID.
------------
$ oracle_login host=10.0.0.1 sid=FILE0 0=sids.txt -x ignore:code=ORA-12505

NB. Against Oracle9, it may crash (Segmentation fault) as soon as a valid SID is
    found (cx_Oracle bug). Sometimes, the SID gets printed out before the crash,
    so try running the same command again if it did not.

}}}
{{{ MySQL

* Brute-force authentication.
-----------
$ mysql_login host=10.0.0.1 user=FILE0 password=FILE0 0=logins.txt -x ignore:fgrep='Access denied for user'

}}}
{{{ PostgresSQL

* Brute-force authentication.
-----------
$ pgsql_login host=10.0.0.1 user=postgres password=FILE0 0=passwords.txt -x ignore:fgrep='password authentication failed'

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
---------                                                (a)
$ vnc_login host=10.0.0.1 password=FILE0 0=passwords.txt --threads 1 \
    -x retry:fgrep!='Authentication failure' --max-retries -1 -x quit:code=0
    (b)                                      (b)              (c)
}}}
{{{ DNS

* Brute-force subdomains.
  (a) Ignore NXDOMAIN responses (rcode 3).
-----------
$ dns_forward name=FILE0.google.com 0=names.txt -x ignore:code=3
                                                (a)
* Brute-force domain with every possible TLDs.
-----------
$ dns_forward name=google.MOD0 0=TLD -x ignore:code=3

* Brute-force SRV records.
-----------
$ dns_forward name=MOD0.microsoft.com 0=SRV qtype=SRV -x ignore:code=3

* Grab the version of several hosts.
-----------
$ dns_forward server=FILE0 0=hosts.txt name=version.bind qtype=txt qclass=ch

* Reverse lookup several networks.
  (a) Ignore names that do not contain 'google.com'.
  (b) Ignore generic PTR records.
-----------
$ dns_reverse host=NET0 0=216.239.32.0-216.239.47.255,8.8.8.0/24 -x ignore:code=3 -x ignore:fgrep!=google.com -x ignore:fgrep=216-239-
                                                                                  (a)                         (b)
}}}
{{{ SNMP

* SNMPv1/2 : Find valid community names.
----------
$ snmp_login host=10.0.0.1 community=FILE0 0=names.txt -x ignore:mesg='No SNMP response received before timeout'


* SNMPv3 : Find valid usernames.
----------
$ snmp_login host=10.0.0.1 version=3 user=FILE0 0=logins.txt -x ignore:mesg=unknownUserName


* SNMPv3 : Find valid passwords.
----------
$ snmp_login host=10.0.0.1 version=3 user=myuser auth_key=FILE0 0=passwords.txt -x ignore:mesg=wrongDigest

NB0. If you get "notInTimeWindow" error messages, increase the retries option.
NB1. SNMPv3 requires passphrases to be at least 8 characters long.

}}}
{{{ Unzip

* Brute-force the ZIP file password (cracking older pkzip encryption used to be not supported in JtR).
----------
$ unzip_pass zipfile=file.zip password=FILE0 0=passwords.txt -x ignore:code!=0

}}}

CHANGELOG
---------

* v0.9 2020/07/26
  - fixed encoding bugs
  - new Dockerfile
  - new --groups and --auto-progress options
  - fixed various issues reported on Github
  - new testing env with docker-compose

* v0.8 2020/03/22
  - new switches (-R, --csv, --xml, --hits)
  - new pathasis option for http_fuzz
  - new rdp_gateway module
  - fixed various issues reported on Github

* v0.7 2017/12/14
  - added Python3 support
  - added Windows support
  - new --timeout and --allow-ignore-failures options
  - switched to multiprocesses instead of threads (for --timeout to work on Windows)
  - new modules: ike_enum, rdp_login, ajp_fuzz, sqlcipher_pass
  - more info added to XML output
  - fixed many bugs

* v0.6 2014/08/25
  - added CSV and XML output formats
  - added module execution time column
  - improved RANGE keyword
  - new modules: rlogin_login, umbrack_crack
  - minor bug fixes/improvements in http_fuzz and smb_login
  - added more TLDs to dns_forward

* v0.5 2013/07/05
  - new modules: mysql_query, tcp_fuzz
  - new RANGE and PROG keywords (supersedes the reading from stdin feature)
  - switched to impacket for mssql_login
  - output more intuitive
  - fixed connection cache
  - minor bug fixes

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
  * replace dnspython|paramiko|IPy with a better module (scapy|libssh2|netaddr... ?) // https://netaddr.readthedocs.org/en/latest/tutorial_01.html
'''

# }}}

# logging {{{
class Logger:
  def __init__(self, queue):
    self.queue = queue
    self.name = multiprocessing.current_process().name

  def send(self, action, *args):
    self.queue.put((self.name, action, args))

  def quit(self):
    self.send('quit')

  def headers(self):
    self.send('headers')

  def result(self, *args):
    self.send('result', *args)

  def save_response(self, *args):
    self.send('save_response', *args)

  def save_hit(self, *args):
    self.send('save_hit', *args)

  def setLevel(self, level):
    self.send('setLevel', level)

  def warn(self, msg):
    self.send('warning', msg)

  def info(self, msg):
    self.send('info', msg)

  def debug(self, msg):
    self.send('debug', msg)

import logging
class TXTFormatter(logging.Formatter):
  def __init__(self, indicatorsfmt):
    self.resultfmt = '%(asctime)s %(name)-7s %(levelname)7s - ' + ' '.join('%%(%s)%ss' % (k, v) for k, v in indicatorsfmt) + ' | %(candidate)-34s | %(num)5s | %(mesg)s'

    super(TXTFormatter, self).__init__(datefmt='%H:%M:%S')

  def format(self, record):
    if not record.msg or record.msg == 'headers':
      fmt = self.resultfmt

    else:
      if record.levelno == logging.DEBUG:
        fmt = '%(asctime)s %(name)-7s %(levelname)7s [%(pname)s] %(message)s'
      else:
        fmt = '%(asctime)s %(name)-7s %(levelname)7s - %(message)s'

    if PY3:
      self._style._fmt = fmt
    else:
      self._fmt = fmt

    pp = {}
    for k, v in record.__dict__.items():
      if k in ['candidate', 'mesg']:
        pp[k] = repr23(v)
      else:
        pp[k] = v

    return super(TXTFormatter, self).format(logging.makeLogRecord(pp))

class CSVFormatter(logging.Formatter):
  def __init__(self, indicatorsfmt):
    fmt = '%(asctime)s,%(levelname)s,'+','.join('%%(%s)s' % name for name, _ in indicatorsfmt)+',%(candidate)s,%(num)s,%(mesg)s'

    super(CSVFormatter, self).__init__(fmt=fmt, datefmt='%H:%M:%S')

  def format(self, record):
    pp = {}
    for k, v in record.__dict__.items():
      if k in ['candidate', 'mesg']:
        pp[k] = '"%s"' % v.replace('"', '""')
      else:
        pp[k] = v

    return super(CSVFormatter, self).format(logging.makeLogRecord(pp))

class XMLFormatter(logging.Formatter):
  def __init__(self, indicatorsfmt):
    fmt = '''<result time="%(asctime)s" level="%(levelname)s">
''' + '\n'.join('  <{0}>%({1})s</{0}>'.format(name.replace(':', '_'), name) for name, _ in indicatorsfmt) + '''
  <candidate>%(candidate)s</candidate>
  <num>%(num)s</num>
  <mesg>%(mesg)s</mesg>
  <target %(target)s/>
</result>'''

    super(XMLFormatter, self).__init__(fmt=fmt, datefmt='%H:%M:%S')

  def format(self, record):
    pp = {}
    for k, v in record.__dict__.items():
      if isinstance(v, str):
        pp[k] = xmlescape(v)
      else:
        pp[k] = v

    return super(XMLFormatter, self).format(logging.makeLogRecord(pp))

class MsgFilter(logging.Filter):

  def filter(self, record):
    if record.msg:
      return 0
    else:
      return 1

def process_logs(queue, indicatorsfmt, argv, log_dir, runtime_file, csv_file, xml_file, hits_file):

  ignore_ctrlc()

  if PY3:
    logging._levelToName[logging.ERROR] = 'FAIL'
    encoding = 'latin1'
  else:
    logging._levelNames[logging.ERROR] = 'FAIL'
    encoding = None

  handler_out = logging.StreamHandler()
  handler_out.setFormatter(TXTFormatter(indicatorsfmt))

  logger = logging.getLogger('patator')
  logger.setLevel(logging.DEBUG)
  logger.addHandler(handler_out)

  names = [name for name, _ in indicatorsfmt] + ['candidate', 'num', 'mesg']

  if runtime_file or log_dir:
    runtime_log = os.path.join(log_dir or '', runtime_file or 'RUNTIME.log')

    with open(runtime_log, 'a') as f:
      f.write('$ %s\n' % ' '.join(argv))

    handler_log = logging.FileHandler(runtime_log, encoding=encoding)
    handler_log.setFormatter(TXTFormatter(indicatorsfmt))

    logger.addHandler(handler_log)

  if csv_file or log_dir:
    results_csv = os.path.join(log_dir or '', csv_file or 'RESULTS.csv')

    if not os.path.exists(results_csv):
      with open(results_csv, 'w') as f:
        f.write('time,level,%s\n' % ','.join(names))

    handler_csv = logging.FileHandler(results_csv, encoding=encoding)
    handler_csv.addFilter(MsgFilter())
    handler_csv.setFormatter(CSVFormatter(indicatorsfmt))

    logger.addHandler(handler_csv)

  if xml_file or log_dir:
    results_xml = os.path.join(log_dir or '', xml_file or 'RESULTS.xml')

    if not os.path.exists(results_xml):
      with open(results_xml, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<root>\n')
        f.write('<start utc=%s local=%s/>\n' % (xmlquoteattr(strfutctime()), xmlquoteattr(strflocaltime())))
        f.write('<cmdline>%s</cmdline>\n' % xmlescape(' '.join(argv)))
        f.write('<module>%s</module>\n' % xmlescape(argv[0]))
        f.write('<options>\n')

        i = 0
        del argv[0]
        while i < len(argv):
          arg = argv[i]
          if arg[0] == '-':
            if arg in ('-d', '--debug', '--allow-ignore-failures', '-y'):
              f.write('  <option type="global" name=%s/>\n' % xmlquoteattr(arg))
            else:
              if not arg.startswith('--') and len(arg) > 2:
                name, value = arg[:2], arg[2:]
              elif '=' in arg:
                name, value = arg.split('=', 1)
              else:
                name, value = arg, argv[i+1]
                i += 1
              f.write('  <option type="global" name=%s>%s</option>\n' % (xmlquoteattr(name), xmlescape(value)))
          else:
            name, value = arg.split('=', 1)
            f.write('  <option type="module" name=%s>%s</option>\n' % (xmlquoteattr(name), xmlescape(value)))
          i += 1
        f.write('</options>\n')
        f.write('<results>\n')

    else:  # remove "</results>...</root>"
      with open(results_xml, 'r+b') as f:
        offset = f.read().find(b'</results>')
        if offset != -1:
          f.seek(offset)
          f.truncate(f.tell())

    handler_xml = logging.FileHandler(results_xml, encoding=encoding)
    handler_xml.addFilter(MsgFilter())
    handler_xml.setFormatter(XMLFormatter(indicatorsfmt))

    logger.addHandler(handler_xml)

  if hits_file:
    if os.path.exists(hits_file):
      os.rename(hits_file, hits_file + '.' + strftime("%Y%m%d%H%M%S", localtime()))

  while True:

    pname, action, args = queue.get()

    if action == 'quit':
      if log_dir:
        with open(os.path.join(log_dir, 'RESULTS.xml'), 'a') as f:
          f.write('</results>\n<stop utc=%s local=%s/>\n</root>\n' % (xmlquoteattr(strfutctime()), xmlquoteattr(strflocaltime())))
      break

    elif action == 'headers':

      logger.info(' '*77)
      logger.info('headers', extra=dict((n, n) for n in names))
      logger.info('-'*77)

    elif action == 'result':

      typ, resp, candidate, num = args

      results = [(name, value) for (name, _), value in zip(indicatorsfmt, resp.indicators())]
      results += [('candidate', candidate), ('num', num), ('mesg', str(resp)), ('target', resp.str_target())]

      if typ == 'fail':
        logger.error(None, extra=dict(results))
      else:
        logger.info(None, extra=dict(results))

    elif action == 'save_response':

      resp, num = args

      if log_dir:
        filename = '%d_%s' % (num, '-'.join(map(str, resp.indicators())))
        with open('%s.txt' % os.path.join(log_dir, filename), 'wb') as f:
          f.write(resp.dump())

    elif action == 'save_hit':
      if hits_file:
        with open(hits_file, 'ab') as f:
          f.write(b(args[0] +'\n'))

    elif action == 'setLevel':
      logger.setLevel(args[0])

    else:  # 'warn', 'info', 'debug'
      getattr(logger, action)(args[0], extra={'pname': pname})

# }}}

# imports {{{
import re
import os
import sys
from time import localtime, gmtime, strftime, sleep, time
from platform import system
from functools import reduce
from operator import mul, itemgetter
from select import select
from itertools import islice, cycle
import string
import random
from decimal import Decimal
from base64 import b64encode
from datetime import timedelta, datetime
import socket
import subprocess
import hashlib
from collections import defaultdict
import multiprocessing
import signal
import ctypes
import glob
from xml.sax.saxutils import escape as xmlescape, quoteattr as xmlquoteattr
from ssl import wrap_socket
from binascii import hexlify, unhexlify

PY3 = sys.version_info >= (3,)

if PY3:
  from queue import Empty, Full
  from urllib.parse import quote, urlencode, urlparse, urlunparse, quote_plus, unquote
  from io import StringIO
  from sys import maxsize as maxint
else:
  from Queue import Empty, Full
  from urllib import quote, urlencode, quote_plus, unquote
  from urlparse import urlparse, urlunparse
  from cStringIO import StringIO
  from sys import maxint

if PY3:  # http://python3porting.com/problems.html
  def b(x):
    if isinstance(x, bytes):
      return x
    else:
      return x.encode('ISO-8859-1', errors='ignore')

  def B(x):
    if isinstance(x, str):
      return x
    else:
      return x.decode('ISO-8859-1', errors='ignore')
else:
  def b(x):
    return x

  def B(x):
    return x

try:
   input = raw_input
except NameError:
   pass

notfound = []
try:
  from IPy import IP
  has_ipy = True
except ImportError:
  has_ipy = False
  notfound.append('IPy')

try:
  # Python 3.4+
  if sys.platform.startswith('win'):
    import multiprocessing.popen_spawn_win32 as forking
  else:
    import multiprocessing.popen_fork as forking
except ImportError:
  import multiprocessing.forking as forking

if sys.platform.startswith('win'):
  # First define a modified version of Popen.
  class _Popen(forking.Popen):
    def __init__(self, *args, **kw):
      if hasattr(sys, 'frozen'):
        # We have to set original _MEIPASS2 value from sys._MEIPASS
        # to get --onefile mode working.
        os.putenv('_MEIPASS2', sys._MEIPASS)
      try:
        super(_Popen, self).__init__(*args, **kw)
      finally:
        if hasattr(sys, 'frozen'):
          # On some platforms (e.g. AIX) 'os.unsetenv()' is not
          # available. In those cases we cannot delete the variable
          # but only set it to the empty string. The bootloader
          # can handle this case.
          if hasattr(os, 'unsetenv'):
            os.unsetenv('_MEIPASS2')
          else:
            os.putenv('_MEIPASS2', '')

  # Second override 'Popen' class with our modified version.
  forking.Popen = _Popen

from multiprocessing.managers import SyncManager

# }}}

# utils {{{
def expand_path(s):
    return os.path.expandvars(os.path.expanduser(s))

def strfutctime():
  return strftime("%Y-%m-%d %H:%M:%S", gmtime())

def strflocaltime():
  return strftime("%Y-%m-%d %H:%M:%S %Z", localtime())

def which(program):
  def is_exe(fpath):
    return os.path.exists(fpath) and os.access(fpath, os.X_OK)

  fpath, fname = os.path.split(program)
  if on_windows() and fname[-4:] != '.exe':
    fname += '.exe'

  if fpath:
    if is_exe(program):
      return program
  else:
    for path in os.environ["PATH"].split(os.pathsep):
      exe_file = os.path.join(path, fname)
      if is_exe(exe_file):
        return exe_file

  return None

def build_logdir(opt_dir, opt_auto, assume_yes):
    if opt_auto:
      return create_time_dir(opt_dir or '/tmp/patator', opt_auto)
    elif opt_dir:
      return create_dir(opt_dir, assume_yes)
    else:
      return None

def create_dir(top_path, assume_yes):
  top_path = os.path.abspath(top_path)
  if os.path.isdir(top_path):
    files = os.listdir(top_path)
    if files:
      if assume_yes or input("Directory '%s' is not empty, do you want to wipe it ? [Y/n]: " % top_path) != 'n':
        for root, dirs, files in os.walk(top_path):
          if dirs:
            print("Directory '%s' contains sub-directories, safely aborting..." % root)
            sys.exit(0)
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
  return fmt % reduce(lambda x, y: divmod(x[0], y) + x[1:], [(seconds,), 60, 60])

def repr23(s):
  if all(True if 0x20 <= ord(c) < 0x7f else False for c in s):
    return s

  if PY3:
    return repr(s.encode('latin1'))[1:]
  else:
    return repr(s)

def md5hex(plain):
  return hashlib.md5(plain).hexdigest()

def sha1hex(plain):
  return hashlib.sha1(plain).hexdigest()

def html_unescape(s):
  if PY3:
    import html
    return html.unescape(s)
  else:
    from HTMLParser import HTMLParser
    h = HTMLParser()
    return h.unescape(s)

def count_lines(filename):
  with open(filename, 'rb') as f:
    lines = 0
    buf_size = 1024 * 1024
    read_f = f.read

    buf = read_f(buf_size)
    while buf:
      lines += buf.count(b'\n')
      buf = read_f(buf_size)

    return lines

# I rewrote itertools.product to avoid memory over-consumption when using large wordlists
def product(xs, *rest):
  if len(rest) == 0:
    for x in xs:
      yield [x]
  else:
    for head in xs:
      for tail in product(*rest):
        yield [head] + tail

class chain:
  def __init__(self, *iterables):
    self.iterables = iterables

  def __iter__(self):
    for iterable in self.iterables:
      for element in iterable:
        yield element

class FileIter:
  def __init__(self, filename):
    self.filename = filename

  def __iter__(self):
    return open(self.filename, 'rb')

def padhex(d):
  x = '%x' % d
  return '0' * (len(x) % 2) + x

# These are examples. You can easily write your own iterator to fit your needs.
# Or using the PROG keyword, you can call an external program such as:
#   - seq(1) from coreutils
#   - http://hashcat.net/wiki/doku.php?id=maskprocessor
#   - john -stdout -i
# For example:
# $ ./dummy_test data=PROG0 0='seq 1 80'
# $ ./dummy_test data=PROG0 0='mp64.bin ?l?l?l',$(mp64.bin --combination ?l?l?l)
class RangeIter:

  def __init__(self, typ, rng, random=None):
    if typ not in ['hex', 'int', 'float', 'letters', 'lower', 'lowercase', 'upper', 'uppercase']:
      raise ValueError('Incorrect range type %r' % typ)

    if typ in ('hex', 'int', 'float'):

      m = re.match('(-?[^-]+)-(-?[^-]+)$', rng) # 5-50 or -5-50 or 5--50 or -5--50
      if not m:
        raise ValueError('Unsupported range %r' % rng)

      mn = m.group(1)
      mx = m.group(2)

      if typ in ('hex', 'int'):

        mn = int(mn, 16 if '0x' in mn else 10)
        mx = int(mx, 16 if '0x' in mx else 10)

        if typ == 'hex':
          fmt = padhex
        elif typ == 'int':
          fmt = '%d'

      elif typ == 'float':
        mn = Decimal(mn)
        mx = Decimal(mx)

      if mn > mx:
        step = -1
      else:
        step = 1

    elif typ == 'letters':
      charset = [c for c in string.ascii_letters]

    elif typ in ('lower', 'lowercase'):
      charset = [c for c in string.ascii_lowercase]

    elif typ in ('upper', 'uppercase'):
      charset = [c for c in string.ascii_uppercase]

    def zrange(start, stop, step, fmt):
      x = start
      while x != stop+step:

        if callable(fmt):
          yield fmt(x)
        else:
          yield fmt % x
        x += step

    def letterrange(first, last, charset):
      for k in range(len(last)):
        for x in product(*[chain(charset)]*(k+1)):
          result = ''.join(x)
          if first:
            if first != result:
              continue
            else:
              first = None
          yield result
          if result == last:
            return

    if typ == 'float':
      precision = max(len(str(x).partition('.')[-1]) for x in (mn, mx))

      fmt = '%%.%df' % precision
      exp = 10**precision
      step *= Decimal(1) / exp

      self.generator = zrange, (mn, mx, step, fmt)
      self.size = int(abs(mx-mn) * exp) + 1

      def random_generator():
        while True:
          yield fmt % (Decimal(random.randint(mn*exp, mx*exp)) / exp)

    elif typ in ('hex', 'int'):
      self.generator = zrange, (mn, mx, step, fmt)
      self.size = abs(mx-mn) + 1

      def random_generator():
        while True:
          yield fmt % random.randint(mn, mx)

    else: # letters, lower, upper
      def count(f):
        total = 0
        i = 0
        for c in f[::-1]:
          z = charset.index(c) + 1
          total += (len(charset)**i)*z
          i += 1
        return total + 1

      first, last = rng.split('-')
      self.generator = letterrange, (first, last, charset)
      self.size = count(last) - count(first) + 1

    if random:
      self.generator = random_generator, ()
      self.size = maxint

  def __iter__(self):
    fn, args = self.generator
    return fn(*args)

  def __len__(self):
    return self.size

class ProgIter:
  def __init__(self, prog):
    self.prog = prog

  def __iter__(self):
    p = subprocess.Popen(self.prog.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout

class Progress:
  def __init__(self):
    self.current = ''
    self.done_count = 0
    self.hits_count = 0
    self.skip_count = 0
    self.fail_count = 0
    self.seconds = [1]*25 # avoid division by zero early bug condition

class TimeoutError(Exception):
  pass

def on_windows():
  return 'Win' in system()

def ignore_ctrlc():
  if on_windows():
    ctypes.windll.kernel32.SetConsoleCtrlHandler(0, 1)
  else:
    signal.signal(signal.SIGINT, signal.SIG_IGN)

def handle_alarm():
  if not on_windows():
    signal.signal(signal.SIGALRM, raise_timeout)

def raise_timeout(signum, frame):
  if signum == signal.SIGALRM:
    raise TimeoutError('timed out')

def enable_alarm(timeout):
  if not on_windows():
    signal.alarm(timeout)

def disable_alarm():
  if not on_windows():
     signal.alarm(0)

# SyncManager.start(initializer) only available since python2.7
class MyManager(SyncManager):
  @classmethod
  def _run_server(cls, registry, address, authkey, serializer, writer, initializer=None, initargs=()):
    ignore_ctrlc()
    super(MyManager, cls)._run_server(registry, address, authkey, serializer, writer)

def ppstr(s):
  if isinstance(s, bytes):
    s = B(s)
  if not isinstance(s, str):
    s = str(s)
  return s.rstrip('\r\n')

def flatten(l):
  r = []
  for x in l:
    if isinstance(x, (list, tuple)):
      r.extend(map(ppstr, x))
    else:
      r.append(ppstr(x))
  return r

def parse_query(qs, keep_blank_values=False, encoding='utf-8', errors='replace'):
  '''Same as urllib.parse.parse_qsl but without replacing '+' with ' '
  '''
  pairs = [s2 for s1 in qs.split('&') for s2 in s1.split(';')]
  r = []

  for name_value in pairs:
    if not name_value:
      continue
    nv = name_value.split('=', 1)
    if len(nv) != 2:
      if keep_blank_values:
        nv.append('')
      else:
        continue
    if len(nv[1]) or keep_blank_values:
      name = unquote(nv[0], encoding=encoding, errors=errors)
      value = unquote(nv[1], encoding=encoding, errors=errors)
      r.append((name, value))
  return r

# }}}

# Controller {{{
class Controller:

  builtin_actions = (
    ('ignore', 'do not report'),
    ('retry', 'try payload again'),
    ('skip', 'stop testing the same keyword value'),
    ('free', 'stop testing the same option value'),
    ('quit', 'terminate execution now'),
    )

  available_encodings = {
    'hex': (lambda s: B(hexlify(s)), 'encode in hexadecimal'),
    'unhex': (lambda s: B(unhexlify(s)), 'decode from hexadecimal'),
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

  def find_range_keys(self, value):
    return map(int, re.findall(r'RANGE(\d)', value))

  def find_prog_keys(self, value):
    return map(int, re.findall(r'PROG(\d)', value))

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
    exe_grp.add_option('--start', dest='start', type='int', default=0, metavar='N', help='start from offset N in the product of all payload sets')
    exe_grp.add_option('--stop', dest='stop', type='int', default=None, metavar='N', help='stop at offset N')
    exe_grp.add_option('--resume', dest='resume', metavar='r1[,rN]*', help='resume previous run')
    exe_grp.add_option('-e', dest='encodings', action='append', default=[], metavar='arg', help='encode everything between two tags, see Syntax below')
    exe_grp.add_option('-C', dest='combo_delim', default=':', metavar='str', help="delimiter string in combo files (default is ':')")
    exe_grp.add_option('-X', dest='condition_delim', default=',', metavar='str', help="delimiter string in conditions (default is ',')")
    exe_grp.add_option('--allow-ignore-failures', dest='allow_ignore_failures', action='store_true', help="failures cannot be ignored with -x (this is by design to avoid false negatives) this option overrides this safeguard")
    exe_grp.add_option('-y', dest='assume_yes', action='store_true', help="automatically answer yes for all questions")

    opt_grp = OptionGroup(parser, 'Optimization')
    opt_grp.add_option('--rate-limit', dest='rate_limit', type='float', default=0, metavar='N', help='wait N seconds between each attempt (default is 0)')
    opt_grp.add_option('--timeout', dest='timeout', type='int', default=0, metavar='N', help='wait N seconds for a response before retrying payload (default is 0)')
    opt_grp.add_option('--max-retries', dest='max_retries', type='int', default=4, metavar='N', help='skip payload after N retries (default is 4) (-1 for unlimited)')
    opt_grp.add_option('-t', '--threads', dest='num_threads', type='int', default=10, metavar='N', help='number of threads (default is 10)')
    opt_grp.add_option('--groups', dest='groups', default='', metavar='', help="default is to iterate over the cartesian product of all payload sets, use this option to iterate over sets simultaneously instead (aka pitchfork), see syntax inside (default is '0,1..n')")

    log_grp = OptionGroup(parser, 'Logging')
    log_grp.add_option('-l', dest='log_dir', metavar='DIR', help="save output and response data into DIR ")
    log_grp.add_option('-L', dest='auto_log', metavar='SFX', help="automatically save into DIR/yyyy-mm-dd/hh:mm:ss_SFX (DIR defaults to '/tmp/patator')")
    log_grp.add_option('-R', dest='runtime_file', metavar='FILE', help="save output to FILE")
    log_grp.add_option('--csv', dest='csv_file', metavar='FILE', help="save CSV results to FILE")
    log_grp.add_option('--xml', dest='xml_file', metavar='FILE', help="save XML results to FILE")
    log_grp.add_option('--hits', dest='hits_file', metavar='FILE', help="save found candidates to FILE")

    dbg_grp = OptionGroup(parser, 'Debugging')
    dbg_grp.add_option('-d', '--debug', dest='debug', action='store_true', help='enable debug messages')
    dbg_grp.add_option('--auto-progress', dest='auto_progress', type='int', default=0, metavar='N', help='automatically display progress every N seconds')

    parser.option_groups.extend([exe_grp, opt_grp, log_grp, dbg_grp])

    return parser

  def parse_usage(self, argv):
    parser = self.usage_parser(argv[0])
    opts, args = parser.parse_args(argv[1:])

    if not len(args) > 0:
      parser.print_usage()
      print('ERROR: wrong usage. Please read the README inside for more information.')
      sys.exit(2)

    return opts, args

  def __init__(self, module, argv):
    self.thread_report = []
    self.thread_progress = []

    self.payload = {}
    self.iter_keys = {}
    self.iter_groups = {}
    self.enc_keys = []

    self.module = module

    opts, args = self.parse_usage(argv)

    self.combo_delim = opts.combo_delim
    self.condition_delim = opts.condition_delim
    self.rate_limit = opts.rate_limit
    self.timeout = opts.timeout
    self.max_retries = opts.max_retries
    self.num_threads = opts.num_threads
    self.start, self.stop = opts.start, opts.stop
    self.allow_ignore_failures = opts.allow_ignore_failures
    self.auto_progress = opts.auto_progress
    self.auto_progress_next = None

    self.resume = [int(i) for i in opts.resume.split(',')] if opts.resume else None

    manager = MyManager()
    manager.start()

    self.ns = manager.Namespace()
    self.ns.actions = {}
    self.ns.free_list = []
    self.ns.skip_list = []
    self.ns.paused = False
    self.ns.quit_now = False
    self.ns.start_time = 0
    self.ns.total_size = 1

    log_queue = multiprocessing.Queue()

    logsvc = multiprocessing.Process(name='LogSvc', target=process_logs, args=(log_queue, module.Response.indicatorsfmt, argv, build_logdir(opts.log_dir, opts.auto_log, opts.assume_yes), opts.runtime_file, opts.csv_file, opts.xml_file, opts.hits_file))
    logsvc.daemon = True
    logsvc.start()

    global logger
    logger = Logger(log_queue)

    if opts.debug:
      logger.setLevel(logging.DEBUG)
    else:
      logger.setLevel(logging.INFO)

    wlists = {}
    kargs = []
    for arg in args: # ('host=NET0', '0=10.0.0.0/24', 'user=COMBO10', 'password=COMBO11', '1=combos.txt', 'name=google.MOD2', '2=TLD')
      logger.debug('arg: %r' % arg)
      for k, v in self.expand_key(arg):
        logger.debug('k: %s, v: %s' % (k, v))

        if k.isdigit():
          wlists[k] = v

        else:
          if v.startswith('@'):
            p = expand_path(v[1:])
            with open(p) as f:
              v = f.read()

          kargs.append((k, v))

    iter_vals = [v for k, v in sorted(wlists.items())]

    logger.debug('kargs: %s' % kargs) # [('host', 'NET0'), ('user', 'COMBO10'), ('password', 'COMBO11'), ('name', 'google.MOD2')]
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
            print('IPy (https://github.com/haypo/python-ipy) is required for using NET keyword.')
            print('Please read the README inside for more information.')
            sys.exit(3)

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
              for i in self.find_range_keys(v):
                if i not in self.iter_keys:
                  self.iter_keys[i] = ('RANGE', iter_vals[i], [])
                self.iter_keys[i][2].append(k)

              else:
                for i in self.find_prog_keys(v):
                  if i not in self.iter_keys:
                    self.iter_keys[i] = ('PROG', iter_vals[i], [])
                  self.iter_keys[i][2].append(k)

                else:
                  self.payload[k] = v

    if self.iter_keys:
      if not opts.groups:
        # default is to iterate over the cartesian product of all payload sets
        opts.groups = ','.join(map(str, self.iter_keys))

      for i, g in enumerate(opts.groups.split(':')):
        ks = list(map(int, g.split(',')))
        for k in ks:
          if k not in self.iter_keys:
            raise ValueError('Unknown keyword number %r' % k)

        self.iter_groups[i] = sorted(ks)

    logger.debug('iter_groups: %s' % self.iter_groups) # {0: [0, 1], 1: [2]}
    logger.debug('iter_keys: %s' % self.iter_keys) # [(0, ('NET', '10.0.0.0/24', ['host'])), (1, ('COMBO', 'combos.txt', [(0, 'user'), (1, 'password')])), (2, ('MOD', 'TLD', ['name']))]
    logger.debug('enc_keys: %s' % self.enc_keys) # [('password', 'ENC', hex), ('header', 'B64', b64encode), ...
    logger.debug('payload: %s' % self.payload) # {'host': 'NET0', 'user': 'COMBO10', 'password': 'COMBO11', 'name': 'google.MOD2'}

    self.iter_groups = sorted(self.iter_groups.items())
    self.iter_keys = sorted(self.iter_keys.items())
    self.available_actions = [k for k, _ in self.builtin_actions + self.module.available_actions]
    self.module_actions = [k for k, _ in self.module.available_actions]

    for x in opts.actions:
      self.update_actions(x)

    logger.debug('actions: %s' % self.ns.actions)

  def update_actions(self, arg):
    ns_actions = self.ns.actions

    actions, conditions = arg.split(':', 1)
    for action in actions.split(','):

      conds = [c.split('=', 1) for c in conditions.split(self.condition_delim)]

      if '=' in action:
        name, opts = action.split('=')
      else:
        name, opts = action, None

      if name not in self.available_actions:
        raise ValueError('Unsupported action %r' % name)

      if name not in ns_actions:
        ns_actions[name] = []

      ns_actions[name].append((conds, opts))

    self.ns.actions = ns_actions

  def lookup_actions(self, resp):
    actions = {}
    for action, conditions in self.ns.actions.items():
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

  def should_free(self, payload):
    # free_list: [[('host', '10.0.0.1')], [('user', 'anonymous')], [('host', '10.0.0.7'),('user','test')], ...
    for l in self.ns.free_list:
      for k, v in l:
        if payload[k] != v:
          break
      else:
        return True

    return False

  def register_free(self, payload, opts):
    self.ns.free_list += [[(k, payload[k]) for k in opts.split('+')]]
    logger.debug('free_list updated: %s' % self.ns.free_list)

  def should_skip(self, prod):
    # skip_list: [[(0, '10.0.0.1')], [(1, 'anonymous')], [(0, '10.0.0.7'), (1, 'test')], ...
    for l in self.ns.skip_list:
      for k, v in l:
        if prod[k] != v:
          break
      else:
        return True

    return False

  def register_skip(self, prod, opts):
    self.ns.skip_list += [[(k, prod[k]) for k in map(int, opts.split('+'))]]
    logger.debug('skip_list updated: %s' % self.ns.skip_list)

  def fire(self):
    logger.info('Starting %s at %s' % (__banner__, strftime('%Y-%m-%d %H:%M %Z', localtime())))

    try:
      self.start_threads()
      self.monitor_progress()
    except KeyboardInterrupt:
      pass
    except:
      logging.exception(sys.exc_info()[1])
    finally:
      self.ns.quit_now = True

    try:
      # waiting for reports enqueued by consumers to be flushed
      while True:
        active = multiprocessing.active_children()
        self.report_progress()
        if not len(active) > 2: # SyncManager and LogSvc
          break
        logger.debug('active: %s' % active)
        sleep(.1)
    except KeyboardInterrupt:
      pass

    if self.ns.total_size >= maxint:
      total_size = -1
    else:
      total_size = self.ns.total_size

    total_time = time() - self.ns.start_time

    hits_count = sum(p.hits_count for p in self.thread_progress)
    done_count = sum(p.done_count for p in self.thread_progress)
    skip_count = sum(p.skip_count for p in self.thread_progress)
    fail_count = sum(p.fail_count for p in self.thread_progress)

    speed_avg = done_count / total_time

    self.show_final()

    logger.info('Hits/Done/Skip/Fail/Size: %d/%d/%d/%d/%d, Avg: %d r/s, Time: %s' % (
      hits_count, done_count, skip_count, fail_count, total_size, speed_avg,
      pprint_seconds(total_time, '%dh %dm %ds')))

    if done_count < total_size:
      resume = []
      for i, p in enumerate(self.thread_progress):
        c = p.done_count + p.skip_count
        if self.resume:
          if i < len(self.resume):
            c += self.resume[i]
        resume.append(str(c))

      logger.info('To resume execution, pass --resume %s' % ','.join(resume))

    logger.quit()
    while len(multiprocessing.active_children()) > 1:
      sleep(.1)

  def push_final(self, resp): pass
  def show_final(self): pass

  def start_threads(self):

    task_queues = [multiprocessing.Queue(maxsize=10000) for _ in range(self.num_threads)]

    # consumers
    for num in range(self.num_threads):
      report_queue = multiprocessing.Queue(maxsize=1000)
      t = multiprocessing.Process(name='Consumer-%d' % num, target=self.consume, args=(task_queues[num], report_queue, logger.queue))
      t.daemon = True
      t.start()
      self.thread_report.append(report_queue)
      self.thread_progress.append(Progress())

    # producer
    t = multiprocessing.Process(name='Producer', target=self.produce, args=(task_queues, logger.queue))
    t.daemon = True
    t.start()

  def produce(self, task_queues, log_queue):

    ignore_ctrlc()

    global logger
    logger = Logger(log_queue)

    def abort(msg):
      logger.warn(msg)
      self.ns.quit_now = True

    psets = {}
    for k, (t, v, _) in self.iter_keys:

      pset = []
      size = 0

      if t in ('FILE', 'COMBO'):
        for name in v.split(','):
          for fpath in sorted(glob.iglob(expand_path(name))):
            if not os.path.isfile(fpath):
              return abort("No such file '%s'" % fpath)

            pset.append(FileIter(fpath))
            size += count_lines(fpath)

      elif t == 'NET':
        pset = [IP(n, make_net=True) for n in v.split(',')]
        size = sum(len(subnet) for subnet in pset)

      elif t == 'MOD':
        elements, size = self.module.available_keys[v]()
        pset = [elements]

      elif t == 'RANGE':
        for r in v.split(','):
          typ, opt = r.split(':', 1)

          try:
            ri = RangeIter(typ, opt)
            size += len(ri)
            pset.append(ri)
          except ValueError as e:
            return abort("Invalid range '%s' of type '%s', %s" % (opt, typ, e))

      elif t == 'PROG':
        m = re.match(r'(.+),(\d+)$', v)
        if m:
          prog, size = m.groups()
        else:
          prog, size = v, maxint

        logger.debug('prog: %s, size: %s' % (prog, size))

        pset = [ProgIter(prog)]
        size = int(size)

      else:
        return abort('Incorrect keyword %r' % t)

      psets[k] = chain(*pset), size

    logger.debug('payload sets: %r' % psets)

    zipit = []
    if not psets:
      total_size = 1
      zipit.append([''])

    else:
      group_sizes = {}
      for i, ks in self.iter_groups:
        group_sizes[i] = reduce(mul, (size for _, size in [psets[k] for k in ks]))

      logger.debug('group_sizes: %s' % group_sizes)

      total_size = max(group_sizes.values())
      biggest, _ = max(group_sizes.items(), key=itemgetter(1))

      for i, ks in self.iter_groups:

        r = []
        for k in ks:
          pset, _ = psets[k]
          r.append(pset)

        it = product(*r)
        if i != biggest:
          it = cycle(it)

        zipit.append(it)

    logger.debug('zipit: %s' % zipit)
    logger.debug('total_size: %d' % total_size)

    if self.stop and total_size > self.stop:
      total_size = self.stop - self.start
    else:
      total_size -= self.start

    if self.resume:
      total_size -= sum(self.resume)

    self.ns.total_size = total_size
    self.ns.start_time = time()

    logger.headers()

    count = 0
    for pp in islice(zip(*zipit), self.start, self.stop):

      if self.ns.quit_now:
        break

      pp = flatten(pp)
      logger.debug('pp: %s' % pp)

      prod = [''] * len(pp)
      for _, ks in self.iter_groups:
        for k in ks:
          prod[k] = pp.pop(0)

      if self.resume:
        idx = count % len(self.resume)
        off = self.resume[idx]

        if count < off * len(self.resume):
          #logger.debug('Skipping %d %s, resume[%d]: %s' % (count, ':'.join(prod), idx, self.resume[idx]))
          count += 1
          continue

      while True:
        if self.ns.quit_now:
          break

        try:
          cid = count % self.num_threads
          task_queues[cid].put_nowait(prod)
          break
        except Full:
          sleep(.1)

      count += 1

    if not self.ns.quit_now:
      for q in task_queues:
        q.put(None)

    logger.debug('producer done')

    while True:
      if self.ns.quit_now:
        for q in task_queues:
          q.cancel_join_thread()
        break
      sleep(.5)

    logger.debug('producer exits')

  def consume(self, task_queue, report_queue, log_queue):

    ignore_ctrlc()
    handle_alarm()

    global logger
    logger = Logger(log_queue)

    module = self.module()

    def shutdown():
      if hasattr(module, '__del__'):
        module.__del__()
      logger.debug('consumer done')

    while True:
      if self.ns.quit_now:
        return shutdown()

      try:
        prod = task_queue.get_nowait()
      except Empty:
        sleep(.1)
        continue

      if prod is None:
        return shutdown()

      payload = self.payload.copy()

      for i, (t, _, keys) in self.iter_keys:
        if t == 'FILE':
          for k in keys:
            payload[k] = payload[k].replace('FILE%d' % i, prod[i])
        elif t == 'NET':
          for k in keys:
            payload[k] = payload[k].replace('NET%d' % i, prod[i])
        elif t == 'COMBO':
          for j, k in keys:
            payload[k] = payload[k].replace('COMBO%d%d' % (i, j), prod[i].split(self.combo_delim, max(j for j, _ in keys))[j])
        elif t == 'MOD':
          for k in keys:
            payload[k] = payload[k].replace('MOD%d' % i, prod[i])
        elif t == 'RANGE':
          for k in keys:
            payload[k] = payload[k].replace('RANGE%d' % i, prod[i])
        elif t == 'PROG':
          for k in keys:
            payload[k] = payload[k].replace('PROG%d' % i, prod[i])

      for k, m, e in self.enc_keys:
        payload[k] = re.sub(r'{0}(.+?){0}'.format(m), lambda m: e(b(m.group(1))), payload[k])

      logger.debug('product: %s' % prod)
      prod_str = ':'.join(prod)

      if self.should_free(payload):
        logger.debug('skipping')
        report_queue.put(('skip', prod_str, None, 0))
        continue

      if self.should_skip(prod):
        logger.debug('skipping')
        report_queue.put(('skip', prod_str, None, 0))
        continue

      try_count = 0
      start_time = time()

      while True:

        while self.ns.paused and not self.ns.quit_now:
          sleep(1)

        if self.ns.quit_now:
          return shutdown()

        if self.rate_limit > 0:
          sleep(self.rate_limit)

        if try_count <= self.max_retries or self.max_retries < 0:

          actions = {}
          try_count += 1

          logger.debug('payload: %s [try %d/%d]' % (payload, try_count, self.max_retries+1))

          try:
            enable_alarm(self.timeout)
            resp = module.execute(**payload)

            disable_alarm()
          except:
            disable_alarm()

            mesg = '%s %s' % sys.exc_info()[:2]
            logger.debug('caught: %s' % mesg)

            #logging.exception(sys.exc_info()[1])

            resp = self.module.Response('xxx', mesg, timing=time()-start_time)

            if hasattr(module, 'reset'):
              module.reset()

            sleep(try_count * .1)
            continue

        else:
          actions = {'fail': None}

        actions.update(self.lookup_actions(resp))
        report_queue.put((actions, prod_str, resp, time() - start_time))

        for name in self.module_actions:
          if name in actions:
            getattr(module, name)(**payload)

        if 'free' in actions:
          self.register_free(payload, actions['free'])
          break

        if 'skip' in actions:
          self.register_skip(prod, actions['skip'])
          break

        if 'fail' in actions:
          break

        if 'quit' in actions:
          return shutdown()

        if 'retry' in actions:
          continue

        break

  def monitor_progress(self):
    # loop until SyncManager, LogSvc and Producer are the only children left alive
    while len(multiprocessing.active_children()) > 3 and not self.ns.quit_now:
      self.report_progress()
      self.monitor_interaction()

  def report_progress(self):
    for i, pq in enumerate(self.thread_report):
      p = self.thread_progress[i]

      while True:

        try:
          actions, current, resp, seconds = pq.get_nowait()
          #logger.info('actions reported: %s' % '+'.join(actions))

        except Empty:
          break

        if actions == 'skip':
          p.skip_count += 1
          continue

        if self.resume:
          offset = p.done_count + self.resume[i]
        else:
          offset = p.done_count

        offset = (offset * self.num_threads) + i + 1 + self.start

        p.current = current
        p.seconds[p.done_count % len(p.seconds)] = seconds

        if 'quit' in actions:
          self.ns.quit_now = True

        if 'fail' in actions:
          if not self.allow_ignore_failures or 'ignore' not in actions:
            logger.result('fail', resp, current, offset)

        elif 'ignore' not in actions:
          logger.result('hit', resp, current, offset)

        if 'fail' in actions:
          p.fail_count += 1

        elif 'retry' in actions:
          continue

        elif 'ignore' not in actions:
          p.hits_count += 1

          logger.save_response(resp, offset)
          logger.save_hit(current)

          self.push_final(resp)

        p.done_count += 1

  def monitor_interaction(self):

    def read_command():
      if on_windows():
        import msvcrt
        if not msvcrt.kbhit():
          sleep(.1)
          return None

        command = msvcrt.getche()
        if command == 'x':
          command += raw_input()

      else:
        i, _, _ = select([sys.stdin], [], [], .1)
        if not i:
          return None
        command = i[0].readline().strip()

      return command

    command = read_command()

    if command is None:
      if self.auto_progress == 0:
        return

      if self.ns.paused:
        self.auto_progress_next = None
        return

      if self.auto_progress_next is None:
        self.auto_progress_next = time() + self.auto_progress
        return

      if time() < self.auto_progress_next:
        return

      self.auto_progress_next = None
      command = ''

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
      self.ns.quit_now = True

    elif command == 'p':
      self.ns.paused = not self.ns.paused
      logger.info(self.ns.paused and 'Paused' or 'Unpaused')

    elif command == 'd':
      logger.setLevel(logging.DEBUG)

    elif command == 'D':
      logger.setLevel(logging.INFO)

    elif command == 'a':
      logger.info(repr(self.ns.actions))

    elif command.startswith('x') or command.startswith('-x'):
      _, arg = command.split(' ', 1)
      try:
        self.update_actions(arg)
      except ValueError:
        logger.warn('usage: x actions:conditions')

    else: # show progress

      thread_progress = self.thread_progress
      num_threads = self.num_threads
      total_size = self.ns.total_size

      total_count = sum(p.done_count+p.skip_count for p in thread_progress)
      speed_avg = num_threads / (sum(sum(p.seconds) / len(p.seconds) for p in thread_progress) / num_threads)
      if total_size >= maxint:
        etc_time = 'inf'
        remain_time = 'inf'
      else:
        remain_seconds = (total_size - total_count) / speed_avg
        remain_time = pprint_seconds(remain_seconds, '%02d:%02d:%02d')
        etc_seconds = datetime.now() + timedelta(seconds=remain_seconds)
        etc_time = etc_seconds.strftime('%H:%M:%S')

      logger.info('Progress: {0:>3}% ({1}/{2}) | Speed: {3:.0f} r/s | ETC: {4} ({5} remaining) {6}'.format(
        total_count * 100 // total_size,
        total_count,
        total_size,
        speed_avg,
        etc_time,
        remain_time,
        self.ns.paused and '| Paused' or ''))

      if command == 'f':
        for i, p in enumerate(thread_progress):
          total_count = p.done_count + p.skip_count
          logger.info(' {0:>3}: {1:>3}% ({2}/{3}) {4}'.format(
            '#%d' % (i+1),
            int(100*total_count/(1.0*total_size/num_threads)),
            total_count,
            total_size/num_threads,
            p.current))

# }}}

# Response_Base {{{
def match_range(size, val):
  if '-' in val:
    size_min, size_max = val.split('-')

    if not size_min and not size_max:
      raise ValueError('Invalid interval')

    elif not size_min: # size == -N
      return size <= float(size_max)

    elif not size_max: # size == N-
      return size >= float(size_min)

    else:
      size_min, size_max = float(size_min), float(size_max)
      if size_min >= size_max:
        raise ValueError('Invalid interval')

      return size_min <= size <= size_max

  else:
    return size == float(val)

class Response_Base:

  available_conditions = (
    ('code', 'match status code'),
    ('size', 'match size (N or N-M or N- or -N)'),
    ('time', 'match time (N or N-M or N- or -N)'),
    ('mesg', 'match message'),
    ('fgrep', 'search for string in mesg'),
    ('egrep', 'search for regex in mesg'),
    )

  indicatorsfmt = [('code', -5), ('size', -4), ('time', 7)]

  def __init__(self, code, mesg, timing=0, trace=None):
    self.code = code
    self.mesg = mesg
    self.time = timing.time if isinstance(timing, Timing) else timing
    self.size = len(mesg)
    self.trace = trace

  def indicators(self):
    return self.code, self.size, '%.3f' % self.time

  def __str__(self):
    return self.mesg

  def match(self, key, val):
    return getattr(self, 'match_'+key)(val)

  def match_code(self, val):
    return re.match('%s$' % val, str(self.code))

  def match_size(self, val):
    return match_range(self.size, val)

  def match_time(self, val):
    return match_range(self.time, val)

  def match_mesg(self, val):
    return val == self.mesg

  def match_fgrep(self, val):
    return val in self.mesg

  def match_egrep(self, val):
    return re.search(val, self.mesg)

  def dump(self):
    return b(self.trace or str(self))

  def str_target(self):
    return ''

class Timing:
  def __enter__(self):
    self.t1 = time()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.time = time() - self.t1

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
    self.cache = {} # '10.0.0.1:22': ('root', conn1), '10.0.0.2:22': ('admin', conn2),
    self.curr = None

  def __del__(self):
    for _, (_, c) in self.cache.items():
      c.close()
    self.cache.clear()

  def bind(self, host, port, *args, **kwargs):

    hp = '%s:%s' % (host, port)
    key = ':'.join(map(str, args))

    if hp in self.cache:
      k, c = self.cache[hp]

      if key == k:
        self.curr = hp, k, c
        return c.fp, c.banner

      else:
        c.close()
        del self.cache[hp]

    self.curr = None

    logger.debug('connect')
    conn = self.connect(host, port, *args, **kwargs)

    self.cache[hp] = (key, conn)
    self.curr = hp, key, conn

    return conn.fp, conn.banner

  def reset(self, **kwargs):
    if self.curr:
      hp, _, c = self.curr

      c.close()
      del self.cache[hp]

      self.curr = None

# }}}

# FTP {{{
from ftplib import FTP, Error as FTP_Error
try:
  from ftplib import FTP_TLS # only available since python 2.7
except ImportError:
  notfound.append('python')

class FTP_login(TCP_Cache):
  '''Brute-force FTP'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt'''
    ''' -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [21]'),
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

    if tls != '0':
      fp.auth()

    return TCP_Connection(fp, banner)

  def execute(self, host, port='21', tls='0', user=None, password=None, timeout='10', persistent='1'):

    try:
      with Timing() as timing:
        fp, resp = self.bind(host, port, tls, timeout=timeout)

      if user is not None or password is not None:
        with Timing() as timing:

          if user is not None:
            resp = fp.sendcmd('USER ' + user)

          if password is not None:
            resp = fp.sendcmd('PASS ' + password)

      logger.debug('No error: %r' % resp)
      self.reset()

    except FTP_Error as e:
      logger.debug('FTP_Error: %s' % e)
      resp = str(e)

    if persistent == '0':
      self.reset()

    code, mesg = resp.split(' ', 1)
    return self.Response(code, mesg, timing)

# }}}

# SSH {{{
try:
  from logging import NullHandler # only available since python 2.7
except ImportError:
  class NullHandler(logging.Handler):
    def emit(self, record):
      pass

try:
  import paramiko
  logging.getLogger('paramiko.transport').addHandler(NullHandler())
except ImportError:
  notfound.append('paramiko')

def load_keyfile(keyfile):
  for cls in (paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey):
    try:
      return cls.from_private_key_file(keyfile)
    except paramiko.SSHException:
      pass
  else:
    raise

class SSH_login(TCP_Cache):
  '''Brute-force SSH'''

  usage_hints = (
    """%prog host=10.0.0.1 user=root password=FILE0 0=passwords.txt -x ignore:mesg='Authentication failed.'""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [22]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('auth_type', 'type of password authentication to use [password|keyboard-interactive|auto]'),
    ('keyfile', 'file with RSA, DSA or ECDSA private key to test'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, user):
    fp = paramiko.Transport('%s:%s' % (host, int(port)))
    fp.start_client()

    return TCP_Connection(fp, fp.remote_version)

  def execute(self, host, port='22', user=None, password=None, auth_type='password', keyfile=None, persistent='1'):

    try:
      with Timing() as timing:
        fp, banner = self.bind(host, port, user)

      if user is not None:

        if keyfile is not None:
          key = load_keyfile(keyfile)

        with Timing() as timing:

          if keyfile is not None:
            fp.auth_publickey(user, key)

          elif password is not None:
            if auth_type == 'password':
              fp.auth_password(user, password, fallback=False)

            elif auth_type == 'keyboard-interactive':
              fp.auth_interactive(user, lambda a, b, c: [password] if len(c) == 1 else [])

            elif auth_type == 'auto':
              fp.auth_password(user, password, fallback=True)

            else:
              raise ValueError('Incorrect auth_type %r' % auth_type)

      logger.debug('No error')
      code, mesg = '0', banner

      self.reset()

    except paramiko.AuthenticationException as e:
      logger.debug('AuthenticationException: %s' % e)
      code, mesg = '1', str(e)

    if persistent == '0':
      self.reset()

    return self.Response(code, mesg, timing)

# }}}

# Telnet {{{
from telnetlib import Telnet

class Telnet_login(TCP_Cache):
  '''Brute-force Telnet'''

  usage_hints = (
    """%prog host=10.0.0.1 inputs='FILE0\\nFILE1' 0=logins.txt 1=passwords.txt"""
    """ prompt_re='login:|Password:' -x ignore:fgrep='Login incorrect'""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [23]'),
    ('inputs', 'list of values to input'),
    ('prompt_re', 'regular expression to match prompts [\w+:]'),
    ('timeout', 'seconds to wait for a response and for prompt_re to match received data [20]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, timeout):
    self.prompt_count = 0
    fp = Telnet(host, int(port), int(timeout))

    return TCP_Connection(fp)

  def execute(self, host, port='23', inputs=None, prompt_re='\w+:', timeout='20', persistent='0'):

    with Timing() as timing:
      fp, _ = self.bind(host, port, timeout=timeout)

    trace = b''
    prompt_re = b(prompt_re)
    timeout = int(timeout)

    if self.prompt_count == 0:
      _, _, raw = fp.expect([prompt_re], timeout=timeout)
      logger.debug('raw banner: %r' % raw)
      trace += raw
      self.prompt_count += 1

    if inputs is not None:
      with Timing() as timing:

        for val in inputs.split(r'\n'):
          logger.debug('input: %s' % val)
          cmd = b(val + '\n') #'\r\x00'
          fp.write(cmd)
          trace += cmd

          _, _, raw = fp.expect([prompt_re], timeout=timeout)
          logger.debug('raw %d: %r' % (self.prompt_count, raw))
          trace += raw
          self.prompt_count += 1

    if persistent == '0':
      self.reset()

    mesg = B(raw).strip()
    return self.Response(0, mesg, timing, trace)

# }}}

# SMTP {{{
from smtplib import SMTP, SMTP_SSL, SMTPException, SMTPResponseException

class SMTP_Base(TCP_Cache):

  available_options = TCP_Cache.available_options
  available_options += (
    ('timeout', 'seconds to wait for a response [10]'),
    ('host', 'target host'),
    ('port', 'target port [25]'),
    ('ssl', 'use SSL [0|1]'),
    ('helo', 'helo or ehlo command to send after connect [skip]'),
    ('starttls', 'send STARTTLS [0|1]'),
    ('user', 'usernames to test'),
    )

  Response = Response_Base

  def connect(self, host, port, ssl, helo, starttls, timeout):

    if ssl == '0':
      if not port:
        port = 25
      fp = SMTP(timeout=int(timeout))
    else:
      if not port:
        port = 465
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

    with Timing() as timing:
      fp, resp = self.bind(host, port, ssl, helo, starttls, timeout=timeout)

    if user is not None:
      with Timing() as timing:
        resp = fp.verify(user)

    if persistent == '0':
      self.reset()

    code, mesg = resp
    return self.Response(code, B(mesg), timing)


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

    with Timing() as timing:
      fp, resp = self.bind(host, port, ssl, helo, starttls, timeout=timeout)

    if mail_from or user is not None:
      with Timing() as timing:
        if mail_from:
          resp = fp.mail(mail_from)
        if user is not None:
          resp = fp.rcpt(user)

    fp.rset()

    if persistent == '0':
      self.reset()

    code, mesg = resp
    return self.Response(code, B(mesg), timing)


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

    with Timing() as timing:
      fp, resp = self.bind(host, port, ssl, helo, starttls, timeout=timeout)

    try:
      if user is not None and password is not None:
        with Timing() as timing:
          resp = fp.login(user, password)

      logger.debug('No error: %s' % str(resp))
      self.reset()

    except SMTPResponseException as e:
      logger.debug('SMTPResponseException: %s' % e)
      resp = e.args

    if persistent == '0':
      self.reset()

    code, mesg = resp
    return self.Response(code, B(mesg), timing)

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
    ('host', 'target host'),
    ('port', 'target port [79]'),
    ('user', 'usernames to test'),
    ('timeout', 'seconds to wait for a response [5]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='79', user='', timeout='5'):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(int(timeout))

    with Timing() as timing:
      s.connect((host, int(port)))

    if user:
      s.send(b(user))
    s.send(b'\r\n')

    raw = b''
    with Timing() as timing:
      while True:
        resp = s.recv(1024)
        if not resp:
          break
        raw += resp

    s.close()

    logger.debug('recv: %r' % raw)

    mesg = B(raw).strip()

    resp = self.Response(0, mesg, timing, raw)
    resp.lines = [l.strip('\r\n') for l in mesg.split('\n')]

    return resp
# }}}

# DCOM {{{
try:
  from impacket.dcerpc.v5.dcomrt import DCOMConnection
  from impacket.dcerpc.v5.dcom import wmi
except ImportError:
  notfound.append('impacket')

class DCOM_login:
  '''Brute-force DCOM'''

  usage_hints = (
    """%prog host=10.0.0.1 user='admin' password=FILE0 0=passwords.txt""",
    )

  available_options = (
    ('host', 'target host'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('domain', 'domains to test'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, user='', password='', domain=''):
    dcom = DCOMConnection(host, user, password, domain)
    try:
      with Timing() as timing:
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        code, mesg = 0, 'OK'
    except Exception as e:
      code, mesg = 1, e.error_string
    dcom.disconnect()
    return self.Response(code, mesg, timing)

# }}}

# LDAP {{{
if not which('ldapsearch'):
  notfound.append('openldap')

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
    ('host', 'target host'),
    ('port', 'target port [389]'),
    ('binddn', 'usernames to test'),
    ('bindpw', 'passwords to test'),
    ('basedn', 'base DN for search'),
    ('ssl', 'use SSL/TLS [0|1]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='389', binddn='', bindpw='', basedn='', ssl='0'):
    uri = 'ldap%s://%s:%s' % ('s' if ssl != '0' else '', host, port)
    cmd = ['ldapsearch', '-H', uri, '-e', 'ppolicy', '-D', binddn, '-w', bindpw, '-b', basedn, '-s', 'one']

    with Timing() as timing:
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'LDAPTLS_REQCERT': 'never'})
      out, err = map(B, p.communicate())
      code = p.returncode

    mesg = (out + err).strip()
    trace = '%s\n[out]\n%s\n[err]\n%s\n' % (' '.join(cmd), out, err)

    return self.Response(code, mesg, timing, trace)

# }}}

# SMB {{{
try:
  from impacket.smbconnection import SMBConnection, SessionError
  from impacket import nt_errors
  from impacket.dcerpc.v5 import transport, lsat, lsad
  from impacket.dcerpc.v5.samr import SID_NAME_USE
  from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
  from impacket.dcerpc.v5.rpcrt import DCERPCException
except ImportError:
  notfound.append('impacket')

class SMB_Connection(TCP_Connection):
  def close(self):
    self.fp.getSMBServer().get_socket().close()

class Response_SMB(Response_Base):
  indicatorsfmt = [('code', -8), ('size', -4), ('time', 6)]

def split_ntlm(password_hash):
    if password_hash:
      if ':' in password_hash:
        lmhash, nthash = password_hash.split(':')
      else:
        lmhash, nthash = 'aad3b435b51404eeaad3b435b51404ee', password_hash
    else:
      lmhash, nthash = '', ''

    return lmhash, nthash

class SMB_login(TCP_Cache):
  '''Brute-force SMB'''

  usage_hints = (
    """%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt"""
    """ -x ignore:fgrep='unknown user name or bad password'""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [139]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('password_hash', "LM/NT hashes to test, at least one hash must be provided ('lm:nt' or ':nt' or 'lm:')"),
    ('domain', 'domain to test'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_SMB

  def connect(self, host, port):
    # if port == 445, impacket will use <host> instead of '*SMBSERVER' as the remote_name
    fp = SMBConnection('*SMBSERVER', host, sess_port=int(port))

    return SMB_Connection(fp)

  def execute(self, host, port='139', user=None, password='', password_hash=None, domain='', persistent='1'):

    with Timing() as timing:
      fp, _ = self.bind(host, port)

    try:
      if user is None:
        fp.login('', '') # retrieve workgroup/domain and computer name
      else:
        with Timing() as timing:
          if password_hash:
            lmhash, nthash = split_ntlm(password_hash)

            fp.login(user, '', domain, lmhash, nthash)
          else:
            fp.login(user, password, domain)

      logger.debug('No error')
      code, mesg = '0', '%s\\%s (%s)' % (fp.getServerDomain(), fp.getServerName(), fp.getServerOS())

      self.reset()

    except SessionError as e:
      code = '%x' % e.getErrorCode()
      mesg = nt_errors.ERROR_MESSAGES[e.getErrorCode()][0]

    if persistent == '0':
      self.reset()

    return self.Response(code, mesg, timing)

class DCE_Connection(TCP_Connection):
  def __init__(self, fp, rpct):
    self.rpct = rpct
    TCP_Connection.__init__(self, fp)

  def close(self):
    self.rpct.get_socket().close()

# impacket/examples/lookupsid.py is much faster because it queries 1000 SIDs per packet
class SMB_lookupsid(TCP_Cache):
  '''Brute-force SMB SID-lookup'''

  usage_hints = (
    '''%prog host=10.0.0.1 sid=S-1-5-21-1234567890-1234567890-1234567890 rid=RANGE0 0=int:500-2000 -x ignore:code=1''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [445]'),
    ('sid', 'SID to test'),
    ('rid', 'RID to test'),
    ('user', 'username to use if auth required'),
    ('password', 'password to use if auth required'),
    ('password_hash', "LM/NT hashes to test, at least one hash must be provided ('lm:nt' or ':nt' or 'lm:')"),
    ('domain', 'domain to test'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, user, password, domain, password_hash, sid):

    lmhash, nthash = split_ntlm(password_hash)

    rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\lsarpc]' % host) # remoteName
    rpctransport.set_dport(port)
    rpctransport.setRemoteHost(host)
    rpctransport.set_credentials(user, password, domain, lmhash, nthash)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(lsat.MSRPC_UUID_LSAT)

    op2 = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)

    if sid is None:
      res = lsad.hLsarQueryInformationPolicy2(dce, op2['PolicyHandle'], lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
      sid = res['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

    self.sid = sid
    self.policy_handle = op2['PolicyHandle']

    return DCE_Connection(dce, rpctransport)

  def execute(self, host, port='445', user='', password='', password_hash=None, domain='', sid=None, rid=None, persistent='1'):

    dce, _ = self.bind(host, port, user, password, domain, password_hash, sid)

    if rid:
      sid = '%s-%s' % (self.sid, rid)
    else:
      sid = self.sid

    try:
      res = lsat.hLsarLookupSids(dce, self.policy_handle, [sid], lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)

      code, names = 0, []
      for n, item in enumerate(res['TranslatedNames']['Names']):
        names.append("%s\\%s (%s)" % (res['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'], SID_NAME_USE.enumItems(item['Use']).name[7:]))

    except DCERPCException:
      code, names = 1, ['unknown'] # STATUS_NONE_MAPPED

    if persistent == '0':
      self.reset()

    return self.Response(code, ', '.join(names))

# }}}

# POP {{{
from poplib import POP3, POP3_SSL, error_proto as pop_error

class POP_Connection(TCP_Connection):
  def close(self):
    if PY3:
      self.fp.close()
    else:
      self.fp.quit()

class POP_login(TCP_Cache):
  '''Brute-force POP3'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:code=-ERR''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [110]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('ssl', 'use SSL [0|1]'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, ssl, timeout):
    if ssl == '0':
      if not port:
        port = 110
      fp = POP3(host, int(port), timeout=int(timeout))
    else:
      if not port:
        port = 995
      fp = POP3_SSL(host, int(port)) # timeout=int(timeout)) # no timeout option in python2

    return POP_Connection(fp, fp.welcome)

  def execute(self, host, port='', ssl='0', user=None, password=None, timeout='10', persistent='1'):

    with Timing() as timing:
      fp, resp = self.bind(host, port, ssl, timeout=timeout)

    try:
      if user is not None or password is not None:
        with Timing() as timing:

          if user is not None:
            resp = fp.user(user)
          if password is not None:
            resp = fp.pass_(password)

      logger.debug('No error: %s' % resp)
      self.reset()

    except pop_error as e:
      logger.debug('pop_error: %s' % e)
      resp = ', '.join(map(B, e.args))

    if persistent == '0':
      self.reset()

    code, mesg = B(resp).split(' ', 1)
    return self.Response(code, mesg, timing)

class POP_passd:
  '''Brute-force poppassd (http://netwinsite.com/poppassd/)'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:code=500''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [106]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='106', user=None, password=None, timeout='10'):

    fp = LineReceiver()
    with Timing() as timing:
      resp = fp.connect(host, int(port), int(timeout))
    trace = resp + '\r\n'

    try:
      if user is not None or password is not None:
        with Timing() as timing:

          if user is not None:
            cmd = 'USER %s' % user
            resp = fp.sendcmd(cmd)
            trace += '%s\r\n%s\r\n' % (cmd, resp)

          if password is not None:
            cmd = 'PASS %s' % password
            resp = fp.sendcmd(cmd)
            trace += '%s\r\n%s\r\n' % (cmd, resp)

    except LineReceiver_Error as e:
      logger.debug('LineReceiver_Error: %s' % e)
      resp = str(e)
      trace += '%s\r\n%s\r\n' % (cmd, resp)

    finally:
      fp.close()

    code, mesg = fp.parse(resp)
    return self.Response(code, mesg, timing, trace)

# }}}

# IMAP {{{
from imaplib import IMAP4, IMAP4_SSL

class IMAP_login:
  '''Brute-force IMAP4'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [143]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('ssl', 'use SSL [0|1]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='', ssl='0', user=None, password=None):
    if ssl == '0':
      if not port:
        port = 143
      klass = IMAP4
    else:
      if not port:
        port = 993
      klass = IMAP4_SSL

    with Timing() as timing:
      fp = klass(host, port)

    code, resp = 0, B(fp.welcome)

    try:
      if user is not None and password is not None:
        with Timing() as timing:
          r = fp.login(user, password)
        code, resp = r[0], ', '.join(map(B, r[1]))

    except IMAP4.error as e:
      logger.debug('imap_error: %s' % e)
      code, resp = 1, ', '.join(map(B, e.args))

    return self.Response(code, resp, timing)

# }}}

# rlogin {{{
class Rlogin_login(TCP_Cache):
  '''Brute-force rlogin'''

  usage_hints = (
    """Please note that rlogin requires to bind a socket to an Internet domain privileged port.""",
    """%prog host=10.0.0.1 user=root luser=FILE0 0=logins.txt""",
    """%prog host=10.0.0.1 user=john password=FILE0 0=passwords.txt""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [513]'),
    ('luser', 'client username [root]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('prompt_re', 'regular expression to match prompts [\w+:]'),
    ('timeout', 'seconds to wait for a response and for prompt_re to match received data [10]'),
    )
  available_options += TCP_Cache.available_options

  Response = Response_Base

  def connect(self, host, port, timeout):
    fp = Telnet()

    for i in range(50):
      try:
        fp.sock = socket.create_connection((host, int(port)), timeout=int(timeout), source_address=('', 1023 - i))
        break
      except socket.error as e:
        if (e.errno, e.strerror) != (98, 'Address already in use'):
          raise e

    self.need_handshake = True

    return TCP_Connection(fp)

  def execute(self, host, port='513', luser='root', user='', password=None, prompt_re='\w+:', timeout='10', persistent='0'):

    fp, _ = self.bind(host, port, timeout=int(timeout))

    trace = b''
    prompt_re = b(prompt_re)
    timeout = int(timeout)

    with Timing() as timing:
      if self.need_handshake:
        fp.write(b('\x00%s\x00%s\x00vt100/9600\x00' % (luser, user)))
        self.need_handshake = False
      else:
        fp.write(b('%s\r' % user))

      _, m, raw = fp.expect([prompt_re], timeout=timeout) # expecting the Password: prompt
      logger.debug('raw: %r' % raw)
      trace += raw

      if m and password is not None:
        fp.write(b('%s\r' % password))
        _, _, raw = fp.expect([prompt_re], timeout=timeout) # expecting the login: prompt
        logger.debug('raw: %r' % raw)
        trace += raw

    if persistent == '0':
      self.reset()

    mesg = B(raw).strip()
    return self.Response(0, mesg, timing, trace)

# }}}

# VMauthd {{{
class LineReceiver_Error(Exception):
  pass

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
    self.sock.sendall(b(cmd + '\r\n'))
    return self.getresp()

  def getresp(self):
    resp = self.sock.recv(1024)
    while not resp.endswith(b'\n'):
      resp += self.sock.recv(1024)

    resp = B(resp).rstrip()
    code, _ = self.parse(resp)

    if not code.isdigit():
      raise Exception('Unexpected response: %r' % resp)

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
    ('host', 'target host'),
    ('port', 'target port [902]'),
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

    with Timing() as timing:
      fp, resp = self.bind(host, port, ssl, timeout=timeout)
    trace = resp + '\r\n'

    try:
      if user is not None or password is not None:
        with Timing() as timing:

          if user is not None:
            cmd = 'USER %s' % user
            resp = fp.sendcmd(cmd)
            trace += '%s\r\n%s\r\n' % (cmd, resp)

          if password is not None:
            cmd = 'PASS %s' % password
            resp = fp.sendcmd(cmd)
            trace += '%s\r\n%s\r\n' % (cmd, resp)

    except LineReceiver_Error as e:
      logger.debug('LineReceiver_Error: %s' % e)
      resp = str(e)
      trace += '%s\r\n%s\r\n' % (cmd, resp)

    if persistent == '0':
      self.reset()

    code, mesg = fp.parse(resp)
    return self.Response(code, mesg, timing, trace)

# }}}

# MySQL {{{
try:
  from MySQLdb import _mysql
except ImportError:
  notfound.append('mysqlclient')

class MySQL_login:
  '''Brute-force MySQL'''

  usage_hints = (
    """%prog host=10.0.0.1 user=FILE0 password=FILE1 0=logins.txt 1=passwords.txt -x ignore:fgrep='Access denied for user'""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [3306]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='3306', user='anony', password='', timeout='10'):

    try:
      with Timing() as timing:
        fp = _mysql.connect(host=host, port=int(port), user=user, passwd=password, connect_timeout=int(timeout))

      resp = '0', fp.get_server_info()

    except _mysql.Error as e:
      logger.debug('MysqlError: %s' % e)
      resp = e.args

    code, mesg = resp
    return self.Response(code, mesg, timing)

class MySQL_query(TCP_Cache):
  '''Brute-force MySQL queries'''

  usage_hints = (
    '''%prog host=10.0.0.1 user=root password=s3cr3t query="select length(load_file('/home/adam/FILE0'))" 0=files.txt -x ignore:size=0''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [3306]'),
    ('user', 'username to use'),
    ('password', 'password to use'),
    ('query', 'SQL query to execute'),
    )

  available_actions = ()

  Response = Response_Base

  def connect(self, host, port, user, password):
    fp = _mysql.connect(host=host, port=int(port), user=user, passwd=password) # db=db
    return TCP_Connection(fp)

  def execute(self, host, port='3306', user='', password='', query='select @@version'):

    fp, _ = self.bind(host, port, user, password)

    with Timing() as timing:
      fp.query(query)

    rs = fp.store_result()
    rows = rs.fetch_row(maxrows=0, how=0)

    logger.debug('fetched %d rows: %s' % (len(rows), rows))

    code, mesg = '0', '\n'.join(', '.join(map(B, r)) for r in filter(any, rows))
    return self.Response(code, mesg, timing)

# }}}

# MSSQL {{{
# I did not use pymssql because neither version 1.x nor 2.0.0b1_dev were multithreads safe (they all segfault)
try:
  from impacket import tds
  from impacket.tds import TDS_ERROR_TOKEN, TDS_LOGINACK_TOKEN
except ImportError:
  notfound.append('pyopenssl')

class MSSQL_login:
  '''Brute-force MSSQL'''

  usage_hints = (
    """%prog host=10.0.0.1 user=sa password=FILE0 0=passwords.txt -x ignore:fgrep='Login failed for user'""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [1433]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('windows_auth', 'use Windows auth [0|1]'),
    ('domain', 'domain to test []'),
    ('password_hash', "LM/NT hashes to test ('lm:nt' or ':nt')"),
    #('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='1433', user='', password='', windows_auth='0', domain='', password_hash=None): #, timeout='10'):

    fp = tds.MSSQL(host, int(port))
    fp.connect()

    with Timing() as timing:
      if windows_auth == '0':
        r = fp.login(None, user, password, None, None, False)
      else:
        r = fp.login(None, user, password, domain, password_hash, True)

    if not r:
      key = fp.replies[TDS_ERROR_TOKEN][0]

      code = key['Number']
      mesg = key['MsgText'].decode('utf-16le')

    else:
      key = fp.replies[TDS_LOGINACK_TOKEN][0]

      code = '0'
      mesg = '%s (%d%d %d%d)' % (key['ProgName'].decode('utf-16le'), key['MajorVer'], key['MinorVer'], key['BuildNumHi'], key['BuildNumLow'])

    fp.disconnect()

    return self.Response(code, mesg, timing)

# }}}

# Oracle {{{
try:
  import cx_Oracle
except ImportError:
  notfound.append('cx_Oracle')

class Response_Oracle(Response_Base):
  indicatorsfmt = [('code', -9), ('size', -4), ('time', 6)]

class Oracle_login:
  '''Brute-force Oracle'''

  usage_hints = (
    '''%prog host=10.0.0.1 sid=FILE0 0=sids.txt -x ignore:code=ORA-12505''',
    '''%prog host=10.0.0.1 user=SYS password=FILE0 0=passwords.txt -x ignore:code=ORA-01017''',
    )

  available_options = (
    ('host', 'hostnames or subnets to target'),
    ('port', 'ports to target [1521]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('sid', 'sid to test'),
    ('service_name', 'service name to test'),
    )
  available_actions = ()

  Response = Response_Oracle

  def execute(self, host, port='1521', user='', password='', sid='', service_name=''):

    if sid:
      dsn = cx_Oracle.makedsn(host=host, port=port, sid=sid)
    elif service_name:
      dsn = cx_Oracle.makedsn(host=host, port=port, service_name=service_name)
    else:
      raise ValueError('Options sid and service_name cannot be both empty')

    try:
      with Timing() as timing:
        fp = cx_Oracle.connect(user, password, dsn, threaded=True)

      code, mesg = '0', fp.version

    except cx_Oracle.DatabaseError as e:
      code, mesg = e.args[0].message[:-1].split(': ', 1)

    return self.Response(code, mesg, timing)

# }}}

# PostgreSQL {{{
try:
  import psycopg2
except ImportError:
  notfound.append('psycopg')

class Pgsql_login:
  '''Brute-force PostgreSQL'''

  usage_hints = (
    """%prog host=10.0.0.1 user=postgres password=FILE0 0=passwords.txt -x ignore:fgrep='password authentication failed for user'""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [5432]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    ('database', 'databases to test [postgres]'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='5432', user=None, password=None, database='postgres', ssl='disable', timeout='10'):

    try:
      with Timing() as timing:
        psycopg2.connect(host=host, port=int(port), user=user, password=password, database=database, sslmode=ssl, connect_timeout=int(timeout))

      code, mesg = '0', 'OK'

    except psycopg2.OperationalError as e:
      logger.debug('OperationalError: %s' % e)
      code, mesg = '1', str(e).strip()

    return self.Response(code, mesg, timing)

# }}}

# HTTP {{{
try:
  import pycurl

  if hasattr(pycurl, 'PRIMARY_PORT'):
    proxytype_mapping = {
      'http': pycurl.PROXYTYPE_HTTP,
      'socks4': pycurl.PROXYTYPE_SOCKS4,
      'socks4a': pycurl.PROXYTYPE_SOCKS4A,
      'socks5': pycurl.PROXYTYPE_SOCKS5,
      'socks5_with_hostname': pycurl.PROXYTYPE_SOCKS5_HOSTNAME,
    }
  else:
    # PRIMARY_PORT available since libcurl-7.21.0 and all PROXY_* since libcurl-7.18
    # PRIMARY_PORT and all PROXY_* available since pycurl-7.19.5.1
    notfound.append('libcurl')
except ImportError:
  notfound.append('pycurl')

class Response_HTTP(Response_Base):

  indicatorsfmt = [('code', -4), ('size:clen', -13), ('time', 6)]

  def __init__(self, code, response, timing=0, trace=None, content_length=-1, target={}):
    Response_Base.__init__(self, code, response, timing, trace=trace)
    self.content_length = content_length
    self.target = target

  def indicators(self):
    return self.code, '%d:%d' % (self.size, self.content_length), '%.3f' % self.time

  def __str__(self):
    lines = re.findall('^(HTTP/.+)$', self.mesg, re.M)
    if lines:
      return lines[-1].rstrip('\r')
    else:
      return self.mesg

  def match_clen(self, val):
    return match_range(self.content_length, val)

  def match_egrep(self, val):
    return re.search(val, self.mesg, re.M)

  def str_target(self):
    return ' '.join('%s=%s' % (k, xmlquoteattr(str(v))) for k, v in self.target.items())

  available_conditions = Response_Base.available_conditions
  available_conditions += (
    ('clen', 'match Content-Length header (N or N-M or N- or -N)'),
    )

try:
  from http.server import BaseHTTPRequestHandler
except ImportError:
  from BaseHTTPServer import BaseHTTPRequestHandler

class HTTPRequestParser(BaseHTTPRequestHandler):
  def __init__(self, fd):
    self.rfile = fd
    self.error = None
    self.body = None

    command, path, version = B(self.rfile.readline()).split()
    self.raw_requestline = b('%s %s %s' % (command, path, 'HTTP/1.1' if version.startswith('HTTP/2') else version))

    self.parse_request()
    self.request_version = version

    if self.command == 'POST':
      self.body = B(self.rfile.read(-1)).rstrip('\r\n')

      if 'Content-Length' in self.headers:
        del self.headers['Content-Length']

  def send_error(self, code, message):
    self.error = message

class Controller_HTTP(Controller):

  def expand_key(self, arg):
    key, val = arg.split('=', 1)
    if key == 'raw_request':

      with open(val, 'rb') as fd:
        r = HTTPRequestParser(fd)

      if r.error:
        raise ValueError('Failed to parse file %r as a raw HTTP request' % val, r.error)

      opts = {}

      if r.path.startswith('http'):
        opts['url'] = r.path
      else:
        _, _, opts['path'], opts['params'], opts['query'], opts['fragment'] = urlparse(r.path)
        opts['host'] = r.headers['Host']

      opts['header'] = str(r.headers)
      opts['method'] = r.command
      opts['body'] = r.body

      for key, val in opts.items():
        if val:
          yield (key, val)

    else:
      yield (key, val)

class HTTP_fuzz(TCP_Cache):
  '''Brute-force HTTP'''

  usage_hints = [
    '''%prog url=http://10.0.0.1/FILE0 0=paths.txt -x ignore:code=404 -x ignore,retry:code=500''',
    '''%prog url=http://10.0.0.1/manager/html user_pass=COMBO00:COMBO01 0=combos.txt -x ignore:code=401''',
    '''%prog url=http://10.0.0.1/phpmyadmin/index.php method=POST'''
    ''' body='pma_username=root&pma_password=FILE0&server=1&lang=en' 0=passwords.txt follow=1'''
    """ accept_cookie=1 -x ignore:fgrep='Cannot log in to the MySQL server'""",
    ]

  available_options = (
    ('url', 'target url (scheme://host[:port]/path?query)'),
    #('host', 'target host'),
    #('port', 'target port'),
    #('path', 'web path [/]'),
    #('query', 'query string'),
    ('body', 'body data'),
    ('header', 'use custom headers'),
    ('method', 'method to use [GET|POST|HEAD|...]'),
    ('raw_request', 'load request from file'),
    ('scheme', 'scheme [http|https]'),
    ('auto_urlencode', 'automatically perform URL-encoding [1|0]'),
    ('pathasis', 'retain sequences of /../ or /./ [0|1]'),
    ('user_pass', 'username and password for HTTP authentication (user:pass)'),
    ('auth_type', 'type of HTTP authentication [basic | digest | ntlm]'),
    ('follow', 'follow any Location redirect [0|1]'),
    ('max_follow', 'redirection limit [5]'),
    ('accept_cookie', 'save received cookies to issue them in future requests [0|1]'),
    ('proxy', 'proxy to use (host:port)'),
    ('proxy_type', 'proxy type [http|socks4|socks4a|socks5]'),
    ('resolve', 'hostname to IP address resolution to use (hostname:IP)'),
    ('ssl_cert', 'client SSL certificate file (cert+key in PEM format)'),
    ('timeout_tcp', 'seconds to wait for a TCP handshake [10]'),
    ('timeout', 'seconds to wait for a HTTP response [20]'),
    ('before_urls', 'comma-separated URLs to query before the main request'),
    ('before_header', 'use a custom header in the before_urls request'),
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

  @staticmethod
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

  def execute(self, url=None, host=None, port='', scheme='http', path='/', params='', query='', fragment='', body='',
    header='', method='GET', auto_urlencode='1', pathasis='0', user_pass='', auth_type='basic',
    follow='0', max_follow='5', accept_cookie='0', proxy='', proxy_type='http', resolve='', ssl_cert='', timeout_tcp='10', timeout='20', persistent='1',
    before_urls='', before_header='', before_egrep='', after_urls='', max_mem='-1'):

    if url:
      scheme, host, path, params, query, fragment = urlparse(url)
      del url

    if host:
      if ':' in host:
        host, port = host.split(':')

    if resolve:
      resolve_host, resolve_ip = resolve.split(':', 1)
      if port:
        resolve_port = port
      else:
        resolve_port = 80

      resolve = '%s:%s:%s' % (resolve_host, resolve_port, resolve_ip)

    if proxy_type in proxytype_mapping:
      proxy_type = proxytype_mapping[proxy_type]
    else:
      raise ValueError('Invalid proxy_type %r' % proxy_type)

    fp, _ = self.bind(host, port, scheme)

    fp.setopt(pycurl.PATH_AS_IS, int(pathasis))
    fp.setopt(pycurl.FOLLOWLOCATION, int(follow))
    fp.setopt(pycurl.MAXREDIRS, int(max_follow))
    fp.setopt(pycurl.CONNECTTIMEOUT, int(timeout_tcp))
    fp.setopt(pycurl.TIMEOUT, int(timeout))
    fp.setopt(pycurl.PROXY, proxy)
    fp.setopt(pycurl.PROXYTYPE, proxy_type)
    fp.setopt(pycurl.RESOLVE, [resolve])

    def noop(buf): pass
    fp.setopt(pycurl.WRITEFUNCTION, noop)

    def debug_func(t, s):
      if max_mem > 0 and trace.tell() > max_mem:
        return 0

      if t not in (pycurl.INFOTYPE_HEADER_OUT, pycurl.INFOTYPE_DATA_OUT, pycurl.INFOTYPE_TEXT, pycurl.INFOTYPE_HEADER_IN, pycurl.INFOTYPE_DATA_IN):
        return 0

      s = B(s)

      if t in (pycurl.INFOTYPE_HEADER_OUT, pycurl.INFOTYPE_DATA_OUT):
        trace.write(s)

      elif t == pycurl.INFOTYPE_TEXT and 'upload completely sent off' in s:
        trace.write('\n\n')

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
        raise ValueError('Incorrect auth_type %r' % auth_type)

    if ssl_cert:
      fp.setopt(pycurl.SSLCERT, ssl_cert)

    if accept_cookie == '1':
      fp.setopt(pycurl.COOKIEFILE, '')
      # warning: do not pass a Cookie: header into HTTPHEADER if using COOKIEFILE as it will
      # produce requests with more than one Cookie: header
      # and the server will process only one of them (eg. Apache only reads the last one)

    if before_urls:
      for before_url in before_urls.split(','):
        self.perform_fp(fp, 'GET', before_url, before_header)

      if before_egrep:
        for be in before_egrep.split('|'):
          mark, regex = be.split(':', 1)
          val = re.search(regex, response.getvalue(), re.M).group(1)

          if auto_urlencode == '1':
            val = html_unescape(val)
            val = quote(val)

          header = header.replace(mark, val)
          query = query.replace(mark, val)
          body = body.replace(mark, val)

      response = StringIO()

    if auto_urlencode == '1':
      path = quote(path)
      query = urlencode(parse_query(query, True))
      body = urlencode(parse_query(body, True))

    if port:
      host = '%s:%s' % (host, port)

    url = urlunparse((scheme, host, path, params, query, fragment))
    self.perform_fp(fp, method, url, header, body)

    target = {}
    target['ip'] = fp.getinfo(pycurl.PRIMARY_IP)
    target['port'] = fp.getinfo(pycurl.PRIMARY_PORT)
    target['hostname'] = host

    for h in header.split('\n'):
      if ': ' in h:
        k, v = h.split(': ', 1)
        if k.lower() == 'host':
          target['vhost'] = v.rstrip('\r')
          break

    if after_urls:
      for after_url in after_urls.split(','):
        self.perform_fp(fp, 'GET', after_url)

    http_code = fp.getinfo(pycurl.HTTP_CODE)
    content_length = fp.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD)
    response_time = fp.getinfo(pycurl.TOTAL_TIME) - fp.getinfo(pycurl.PRETRANSFER_TIME)

    if persistent == '0':
      self.reset()

    return self.Response(http_code, response.getvalue(), response_time, trace.getvalue(), content_length, target)

# }}}

# RDP Gateway {{{
import uuid

class RDP_gateway(HTTP_fuzz):
  '''Brute-force RDP Gateway'''

  usage_hints = (
      '''%prog url='https://example.com/remoteDesktopGateway/' user_pass=COMBO00:COMBO01 0=combos.txt -x ignore:code=401''',
    )

  @staticmethod
  def perform_fp(fp, method, url, header='', body=''):
    method = 'RDG_OUT_DATA'
    header += '\nRDG-Connection-Id: {%s}' % uuid.uuid4()

    # if authentication is successful the gateway server hangs and won't send a body
    fp.setopt(pycurl.NOBODY, 1)

    HTTP_fuzz.perform_fp(fp, method, url, header)

# }}}

# AJP {{{
try:
  from ajpy.ajp import AjpForwardRequest
except ImportError:
  notfound.append('ajpy')

class AJP_Connection(TCP_Connection):
  def close(self):
    sock, stream = self.fp
    sock.close()

class Response_AJP(Response_HTTP):
  def __init__(self, code, response, timing=0, trace=None, content_length=-1, target={}):
    Response_HTTP.__init__(self, code, response, timing, trace, content_length, target)

  def __str__(self):
    lines = self.mesg.splitlines()
    if lines:
      return lines[0].rstrip('\r')
    else:
      return self.mesg

def prepare_ajp_forward_request(target_host, req_uri, method):
  fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
  fr.method = method
  fr.protocol = 'HTTP/1.1'
  fr.req_uri = req_uri
  fr.remote_addr = target_host
  fr.remote_host = None
  fr.server_name = target_host
  fr.server_port = 80
  fr.request_headers = {
    'SC_REQ_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'SC_REQ_CONNECTION': 'keep-alive',
    'SC_REQ_CONTENT_LENGTH': '0',
    'SC_REQ_HOST': target_host,
    'SC_REQ_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0',
    'Accept-Encoding': 'gzip, deflate, sdch',
    'Accept-Language': 'en-US,en;q=0.5',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0'
  }
  fr.is_ssl = False
  fr.attributes = []

  return fr

class AJP_fuzz(TCP_Cache):
  '''Brute-force AJP'''

  usage_hints = [
    '''%prog url=ajp://10.0.0.1/FILE0 0=paths.txt -x ignore:code=404 -x ignore,retry:code=500''',
    '''%prog url=ajp://10.0.0.1/manager/html user_pass=COMBO00:COMBO01 0=combos.txt -x ignore:code=401''',
    ]

  available_options = (
    ('url', 'target url (ajp://host[:port]/path?query)'),
    ('header', 'use custom headers'),
    ('user_pass', 'username and password for HTTP authentication (user:pass)'),
    )

  Response = Response_AJP

  def connect(self, host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.connect((host, int(port)))
    stream = sock.makefile('rb', None if PY3 else 0)

    return AJP_Connection((sock, stream))

  def execute(self, url=None, host=None, port='8009', path='/', params='', query='', header='', user_pass='', persistent='1'):

    if url:
      scheme, host, path, params, query, fragment = urlparse(url)
      if ':' in host:
        host, port = host.split(':')
      del url

    req_uri = urlunparse(('', '', path, params, query, fragment))

    fr = prepare_ajp_forward_request(host, req_uri, AjpForwardRequest.REQUEST_METHODS.get('GET'))
    fr.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + B(b64encode(b(user_pass)))

    headers = [h.strip('\r') for h in header.split('\n') if h]
    for h in headers:
      k, _, v = h.partition(':')
      fr.request_headers[k] = v

    (sock, stream), _ = self.bind(host, port)

    with Timing() as timing:
      responses = fr.send_and_receive(sock, stream)

    snd_hdrs_res = responses[0]
    http_code = snd_hdrs_res.http_status_code
    http_status_msg = B(snd_hdrs_res.http_status_msg)
    content_length = int(snd_hdrs_res.response_headers.get('Content-Length', 0))

    data_res = responses[1:-1]
    data = ''
    for dr in data_res:
      data += B(dr.data)

    target = {}
    target['ip'] = host
    target['port'] = port

    if persistent == '0':
      self.reset()

    return self.Response(http_code, http_status_msg + '\n' + data, timing, data, content_length, target)

# }}}

# RDP {{{
if not which('xfreerdp'):
  notfound.append('xfreerdp')

class RDP_login:
  '''Brute-force RDP (NLA)'''

  usage_hints = (
    '''%prog host=10.0.0.1 user='administrator' password=FILE0 0=passwords.txt''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [3389]'),
    ('user', 'usernames to test'),
    ('password', 'passwords to test'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port='3389', user=None, password=None):

    cmd = ['xfreerdp', '/v:%s:%d' % (host, int(port)), '/u:%s' % user, '/p:%s' % password, '/cert-ignore', '+auth-only', '/sec:nla', '/log-level:error']

    with Timing() as timing:
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = map(B, p.communicate())
      code = p.returncode

    m = re.search(' (ERR.+?) ', err)
    if m:
      err = m.group(1)
    elif 'Authentication only, exit status 0' in err:
      err = 'OK'

    mesg = (out + err).strip()
    trace = '%s\n[out]\n%s\n[err]\n%s\n' % (' '.join(cmd), out, err)

    return self.Response(code, mesg, timing, trace)

# }}}

# VNC {{{
try:
  from Cryptodome.Cipher import DES
except ImportError:
  notfound.append('pycrypto')

class VNC_Error(Exception):
  pass

class VNC:
  def connect(self, host, port, timeout):
    self.fp = socket.create_connection((host, port), timeout=timeout)
    resp = self.fp.recv(99) # banner

    logger.debug('banner: %r' % resp)
    self.version = B(resp[:11])

    if len(resp) > 12:
      raise VNC_Error('%s %r' % (self.version, B(resp[12:])))

    return self.version

  def login(self, password):
    logger.debug('Remote version: %r' % self.version)
    major, minor = self.version[6], self.version[10]

    if (major, minor) in [('3', '8'), ('4', '1')]:
      proto = 'RFB 003.008\n'

    elif (major, minor) == ('3', '7'):
      proto = 'RFB 003.007\n'

    else:
      proto = 'RFB 003.003\n'

    logger.debug('Client version: %r' % proto[:-1])
    self.fp.sendall(b(proto))

    sleep(0.5)

    resp = self.fp.recv(99)
    logger.debug('Security types supported: %r' % resp)

    if major == '4' or (major == '3' and int(minor) >= 7):
      code = ord(resp[0:1])
      if code == 0:
        raise VNC_Error('Session setup failed: %s' % B(resp))

      self.fp.sendall(b'\x02') # always use classic VNC authentication
      resp = self.fp.recv(99)

    else: # minor == '3':
      code = ord(resp[3:4])
      if code != 2:
        raise VNC_Error('Session setup failed: %s' % B(resp))

      resp = resp[-16:]

    if len(resp) != 16:
      raise VNC_Error('Unexpected challenge size (No authentication required? Unsupported authentication type?)')

    logger.debug('challenge: %r' % resp)
    pw = password.ljust(8, '\x00')[:8] # make sure it is 8 chars long, zero padded

    key = self.gen_key(pw)
    logger.debug('key: %r' % key)

    des = DES.new(key, DES.MODE_ECB)
    enc = des.encrypt(resp)

    logger.debug('enc: %r' % enc)
    self.fp.sendall(enc)

    resp = self.fp.recv(99)
    logger.debug('resp: %r' % resp)

    code = ord(resp[3:4])
    mesg = B(resp[8:])

    if code == 1:
      return code, mesg or 'Authentication failure'

    elif code == 0:
      return code, mesg or 'OK'

    else:
      raise VNC_Error('Unknown response: %r (code: %s)' % (resp, code))

  def gen_key(self, key):
    newkey = []
    for ki in range(len(key)):
      bsrc = ord(key[ki])
      btgt = 0
      for i in range(8):
        if bsrc & (1 << i):
          btgt = btgt | (1 << 7-i)
      newkey.append(btgt)

    if PY3:
      return bytes(newkey)
    else:
      return ''.join(chr(c) for c in newkey)

class VNC_login:
  '''Brute-force VNC'''

  usage_hints = (
    '''%prog host=10.0.0.1 password=FILE0 0=passwords.txt -t 1 -x 'retry:fgrep!=Authentication failure' --max-retries -1 -x quit:code=0''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [5900]'),
    ('password', 'passwords to test'),
    ('timeout', 'seconds to wait for a response [10]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port=None, password=None, timeout='10'):
    v = VNC()

    try:
      with Timing() as timing:
        code, mesg = 0, v.connect(host, int(port or 5900), int(timeout))

      if password is not None:
        with Timing() as timing:
          code, mesg = v.login(password)

    except VNC_Error as e:
      logger.debug('VNC_Error: %s' % e)
      code, mesg = 2, str(e)

    return self.Response(code, mesg, timing)

# }}}

# DNS {{{
try:
  import dns.rdatatype
  import dns.message
  import dns.query
  import dns.reversename
except ImportError:
  notfound.append('dnspython')

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
  # NB. does not return an exhaustive list (ie. missing co.uk, co.nz etc.)

  from itertools import product
  from string import ascii_lowercase

  # http://data.iana.org/TLD/tlds-alpha-by-domain.txt
  gtld = ['academy', 'actor', 'aero', 'agency', 'archi', 'arpa', 'asia', 'axa',
    'bar', 'bargains', 'berlin', 'best', 'bid', 'bike', 'biz', 'black', 'blue',
    'boutique', 'build', 'builders', 'buzz', 'cab', 'camera', 'camp', 'cards',
    'careers', 'cat', 'catering', 'center', 'ceo', 'cheap', 'christmas',
    'cleaning', 'clothing', 'club', 'codes', 'coffee', 'cologne', 'com',
    'community', 'company', 'computer', 'condos', 'construction', 'contractors',
    'cooking', 'cool', 'coop', 'country', 'cruises', 'dance', 'dating', 'democrat',
    'diamonds', 'directory', 'dnp', 'domains', 'edu', 'education', 'email',
    'enterprises', 'equipment', 'estate', 'events', 'expert', 'exposed', 'farm',
    'fish', 'fishing', 'flights', 'florist', 'foundation', 'futbol', 'gallery',
    'gift', 'glass', 'gov', 'graphics', 'guitars', 'guru', 'haus', 'holdings',
    'holiday', 'horse', 'house', 'immobilien', 'industries', 'info', 'ink',
    'institute', 'int', 'international', 'jetzt', 'jobs', 'kaufen', 'kim',
    'kitchen', 'kiwi', 'koeln', 'kred', 'land', 'lighting', 'limo', 'link',
    'london', 'luxury', 'maison', 'management', 'mango', 'marketing', 'meet',
    'menu', 'miami', 'mil', 'mobi', 'moda', 'moe', 'monash', 'museum', 'nagoya',
    'name', 'net', 'neustar', 'ninja', 'nyc', 'okinawa', 'onl', 'org', 'partners',
    'parts', 'photo', 'photography', 'photos', 'pics', 'pink', 'plumbing', 'post',
    'pro', 'productions', 'properties', 'pub', 'qpon', 'recipes', 'red', 'ren',
    'rentals', 'repair', 'report', 'reviews', 'rich', 'rodeo', 'ruhr', 'sexy',
    'shiksha', 'shoes', 'singles', 'social', 'sohu', 'solar', 'solutions',
    'supplies', 'supply', 'support', 'systems', 'tattoo', 'technology', 'tel',
    'tienda', 'tips', 'today', 'tokyo', 'tools', 'trade', 'training', 'travel',
    'uno', 'vacations', 'vegas', 'ventures', 'viajes', 'villas', 'vision', 'vodka',
    'vote', 'voting', 'voto', 'voyage', 'wang', 'watch', 'webcam', 'wed', 'wien',
    'wiki', 'works', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--45brj9c',
    'xn--55qw42g', 'xn--55qx5d', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80ao21a',
    'xn--80asehdb', 'xn--80aswg', 'xn--90a3ac', 'xn--c1avg', 'xn--cg4bki',
    'xn--clchc0ea0b2g2a9gcd', 'xn--czru2d', 'xn--d1acj3b', 'xn--fiq228c5hs',
    'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s', 'xn--fpcrj9c3d', 'xn--fzc2c9e2c',
    'xn--gecrj9c', 'xn--h2brj9c', 'xn--i1b6b1a6a2e', 'xn--io0a7i', 'xn--j1amh',
    'xn--j6w193g', 'xn--kprw13d', 'xn--kpry57d', 'xn--l1acc', 'xn--lgbbat1ad8j',
    'xn--mgb9awbf', 'xn--mgba3a4f16a', 'xn--mgbaam7a8h', 'xn--mgbab2bd',
    'xn--mgbayh7gpa', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgberp4a5d4ar',
    'xn--mgbx4cd0ab', 'xn--ngbc5azd', 'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--o3cw4h',
    'xn--ogbpf8fl', 'xn--p1ai', 'xn--pgbs0dh', 'xn--q9jyb4c', 'xn--rhqv96g',
    'xn--s9brj9c', 'xn--unup4y', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xkc2al3hye2a',
    'xn--xkc2dl3a5ee0h', 'xn--yfro4i67o', 'xn--ygbi2ammx', 'xn--zfr164b', 'xxx',
    'xyz', 'zone']

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
    for filepath in files:
      if not os.path.isfile(filepath):
        logger.warn("File '%s' is missing, there will be less records to test" % filepath)
        continue
      with open(filepath, 'rb') as f:
        for line in f:
          match = re.match(r'([a-zA-Z0-9]+)\s', B(line))
          if not match:
            continue
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
      if line:
        line += ' / '
      line += ' '.join(map(str, self.ip))
    if self.alias:
      if line:
        line += ' / '
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
        if d not in domains:
          domains[d] = 0
        domains[d] += 1

    for domain, count in sorted(domains.items(), key=lambda a: a[0].split('.')[-1::-1]):
      print('%34s %d' % (domain, count))

    print('Networks ' + '-'*41)
    nets = {}
    for ip in set(ipmap):
      if not ip.version() == 4:
        nets[ip] = [ip]
      else:
        n = ip.make_net('255.255.255.0')
        if n not in nets:
          nets[n] = []
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
  '''Reverse DNS lookup'''

  usage_hints = [
    '''%prog host=NET0 0=192.168.0.0/24 -x ignore:code=3''',
    '''%prog host=NET0 0=216.239.32.0-216.239.47.255,8.8.8.0/24 -x ignore:code=3 -x ignore:fgrep!=google.com -x ignore:fgrep=216-239-''',
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

    with Timing() as timing:
      response = dns_query(server, int(timeout), protocol, dns.reversename.from_address(host), qtype='PTR', qclass='IN')

    code = response.rcode()
    status = dns.rcode.to_text(code)
    rrs = [[host, c, t, d] for _, _, c, t, d in [rr.to_text().split(' ', 4) for rr in response.answer]]

    mesg = '%s %s' % (status, ''.join('[%s]' % ' '.join(rr) for rr in rrs))
    resp = self.Response(code, mesg, timing)

    resp.rrs = rrs

    return resp

class DNS_forward:
  '''Forward DNS lookup'''

  usage_hints = [
    '''%prog name=FILE0.google.com 0=names.txt -x ignore:code=3''',
    '''%prog name=google.MOD0 0=TLD -x ignore:code=3''',
    '''%prog name=MOD0.microsoft.com 0=SRV qtype=SRV -x ignore:code=3''',
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

    with Timing() as timing:
      response = dns_query(server, int(timeout), protocol, name, qtype=qtype, qclass=qclass)

    code = response.rcode()
    status = dns.rcode.to_text(code)
    rrs = [[n, c, t, d] for n, _, c, t, d in [rr.to_text().split(' ', 4) for rr in response.answer + response.additional + response.authority]]

    mesg = '%s %s' % (status, ''.join('[%s]' % ' '.join(rr) for rr in rrs))
    resp = self.Response(code, mesg, timing)

    resp.rrs = rrs

    return resp

# }}}

# SNMP {{{
try:
  from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UsmUserData
  from pysnmp.hlapi import UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
  from pysnmp.hlapi import usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, usmHMAC384SHA512AuthProtocol
  from pysnmp.hlapi import usmDESPrivProtocol, usmAesCfb128Protocol

  SNMP_AUTHPROTO = {'md5': usmHMACMD5AuthProtocol, 'sha': usmHMACSHAAuthProtocol, 'sha512': usmHMAC384SHA512AuthProtocol}
  SNMP_PRIVPROTO = {'des': usmDESPrivProtocol, 'aes': usmAesCfb128Protocol}
except ImportError:
  notfound.append('pysnmp')

try:
  import pyasn1
except ImportError:
  notfound.append('pyasn1')

class SNMP_login:
  '''Brute-force SNMP v1/2/3'''

  usage_hints = (
    """%prog host=10.0.0.1 version=2 community=FILE0 0=names.txt -x ignore:mesg='No SNMP response received before timeout'""",
    """%prog host=10.0.0.1 version=3 user=FILE0 0=logins.txt -x ignore:mesg=unknownUserName""",
    """%prog host=10.0.0.1 version=3 user=myuser auth_key=FILE0 0=passwords.txt -x ignore:mesg=wrongDigest""",
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [161]'),
    ('version', 'SNMP version to use [2|3|1]'),
    ('community', 'SNMPv1/2c community names to test [public]'),
    ('user', 'SNMPv3 usernames to test [op5user]'),
    ('auth_key', 'SNMPv3 passwords to test [authPass]'),
    ('auth_proto', 'SNMPv3 authentication protocol [md5|sha|sha512]'),
    ('priv_key', 'SNMPv3 encryption key'),
    ('priv_proto', 'SNMPv3 encryption protocol [des|aes]'),
    ('timeout', 'seconds to wait for a response [1]'),
    ('retries', 'number of successive request retries [2]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port=None, version='2', community='public', user='op5user', auth_key='authPass', auth_proto='md5', priv_key='', priv_proto='des', timeout='1', retries='2'):
    if version in ('1', '2', '2c'):
      security_model = CommunityData(community, mpModel=0 if version == '1' else 1)

    elif version == '3':
      if auth_proto not in SNMP_AUTHPROTO:
        raise ValueError('Unsupported SNMPv3 auth protocol %r' % auth_proto)
      if priv_proto not in SNMP_PRIVPROTO:
        raise ValueError('Unsupported SNMPv3 priv protocol %r' % priv_proto)

      if len(auth_key) < 8 or priv_key and len(priv_key) < 8:
        return self.Response('1', 'SNMPv3 requires passwords to be at least 8 characters long')

      kwargs = dict(authKey=auth_key, authProtocol=SNMP_AUTHPROTO[auth_proto])
      if priv_key:
        kwargs.update(dict(privKey=priv_key, privProtocol=SNMP_PRIVPROTO[priv_proto]))

      security_model = UsmUserData(user, **kwargs)

    else:
      raise ValueError('Incorrect SNMP version %r' % version)

    with Timing() as timing:
      errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(
          SnmpEngine(),
          security_model,
          UdpTransportTarget((host, int(port or 161)), timeout=int(timeout), retries=int(retries)),
          ContextData(),
          ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))) #(1, 3, 6, 1, 2, 1, 1, 1, 0)
        )

    if errorIndication:
      mesg = '%s' % errorIndication
    elif errorStatus:
      mesg = '%s' % (errorStatus.prettyPrint())
      if errorIndex > 0:
        mesg += ' %s' % varBinds[int(errorIndex) - 1][0]
    else:
      mesg = ''.join(' = '.join([x.prettyPrint() for x in varBind]) for varBind in varBinds)

    return self.Response(int(errorStatus), mesg, timing)

# }}}

# IKE {{{
if not which('ike-scan'):
  notfound.append('ike-scan')

# http://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml (except for vendor specifics.) These transforms below are IKEv1 only. IKEv2 is not assessed.
IKE_ENC   = [('1', 'DES'), ('2', 'IDEA'), ('3', 'BLOWFISH'), ('4', 'RC5'), ('5', '3DES'), ('6', 'CAST'), ('7/128', 'AES128'), ('7/192', 'AES192'), ('7/256', 'AES256'), ('8', 'Camellia'),
            ('65001', 'Mars'), ('65002', 'RC6'), ('65004', 'Serpent'), ('65005', 'Twofish')]
IKE_HASH  = [('1', 'MD5'), ('2', 'SHA1'), ('3', 'Tiger'), ('4', 'SHA2-256'), ('5', 'SHA2-384'), ('6', 'SHA2-512')]
IKE_AUTH  = [('1', 'PSK'), ('2', 'DSS-Sig'), ('3', 'RSA-Sig'), ('4', 'RSA-Enc'), ('5', 'Revised-RSA-Enc'),
            ('6', 'EIGAMEL-Enc'), ('7', 'Revised-EIGAMEL-Enc'), #('8', 'ECDSA-Sig'), # Reserved
            #('9', 'ECDSA-SHA-256'), ('10', 'ECDSA-SHA-384'), ('11', 'ECDSA-SHA-512'), # RFC4754
            ('128', 'Harkins-CRACK'), # https://tools.ietf.org/html/draft-harkins-ipsec-ike-crack-00.txt
            ('64221', 'Hybrid-RSA-Sig'), ('64223', 'Hybrid-DSS-Sig'), ('65001', 'XAUTH&PSK')] #, ('65003', 'XAUTH&DSS-Sig'), ('65005', 'XAUTH&RSA-Sig'), ('65007', 'XAUTH&RSA-Enc'), ('65009', 'XAUTH&Revised-RSA-Enc')]
IKE_GROUP = [('1', 'modp768'), ('2', 'modp1024'), ('5', 'modp1536'),
            #('3', 'ec2n155'), ('4', 'ec2n185'),
            # ('6', 'ec2n163'), ('7', 'ec2n163'), ('8', 'ec2n283'), ('9', 'ec2n283'), ('10', 'ec2n409'), ('11', 'ec2n409'), ('12', 'ec2n571'), ('13', 'ec2n571'), # only in draft, not RFC
            ('14', 'modp2048')] #, ('15', 'modp3072'), ('16', 'modp4096'), ('17', 'modp6144'), ('18', 'modp8192')] # RFC3526
            # ('19', 'ecp256'), ('20', 'ecp384'), ('21', 'ecp521'), ('22', 'modp1024s160'), ('23', 'modp2048s224'), ('24', 'modp2048s256'), ('25', 'ecp192'), ('26', 'ecp224'), # RFC5903
            # ('27', 'brainpoolP224r1'), ('28', 'brainpoolP256r1'), ('29', 'brainpoolP384r1'), ('30', 'brainpoolP512r1')] # RFC6932

def generate_transforms():
  lists = list(map(lambda l: [i[0] for i in l], [IKE_ENC, IKE_HASH, IKE_AUTH, IKE_GROUP]))
  return map(lambda p: ','.join(p), product(*[chain(l) for l in lists])), reduce(lambda x, y: x*y, map(len, lists))

class Controller_IKE(Controller):

  results = defaultdict(list)

  def show_final(self):
    ''' Expected output:
+ 10.0.0.1:500 (Main Mode)
    Encryption       Hash         Auth      Group
    ---------- ----------   ---------- ----------
          3DES        MD5          PSK   modp1024
          3DES        MD5        XAUTH   modp1024
        AES128       SHA1          PSK   modp1024
        AES128       SHA1        XAUTH   modp1024

+ 10.0.0.1:500 (Aggressive Mode)
    Encryption       Hash         Auth      Group
    ---------- ----------   ---------- ----------
          3DES        MD5          PSK   modp1024
          3DES        MD5        XAUTH   modp1024
        AES128       SHA1          PSK   modp1024
        AES128       SHA1        XAUTH   modp1024
    '''

    ike_enc = dict(IKE_ENC)
    ike_hsh = dict(IKE_HASH)
    ike_ath = dict(IKE_AUTH)
    ike_grp = dict(IKE_GROUP)

    for endpoint, transforms in self.results.items():
      print('\n+ %s' % endpoint)
      print('    %10s %10s %12s %10s' % ('Encryption', 'Hash', 'Auth', 'Group'))
      print('    %10s %10s %12s %10s' % ('-'*10, '-'*10, '-'*10, '-'*10))
      for transform in transforms:
        e, h, a, g = transform.split(',')
        enc = ike_enc[e]
        hsh = ike_hsh[h]
        ath = ike_ath[a]
        grp = ike_grp[g]
        print('    %10s %10s %12s %10s' % (enc, hsh, ath, grp))

  def push_final(self, resp):
    if hasattr(resp, 'rrs'):
      endpoint, transform = resp.rrs
      self.results[endpoint].append(transform)

class IKE_enum:
  '''Enumerate IKE transforms'''

  usage_hints = [
    '''%prog host=10.0.0.1 transform=MOD0 0=TRANS -x ignore:fgrep=NO-PROPOSAL''',
    '''%prog host=10.0.0.1 transform=MOD0 0=TRANS -x ignore:fgrep=NO-PROPOSAL aggressive=RANGE1 1=int:0-1''',
    ]

  available_options = (
    ('host', 'target host'),
    ('port', 'target port [500]'),
    ('transform', 'transform to test [5,1,1,2]'),
    ('aggressive', 'use aggressive mode [0|1]'),
    ('groupname', 'identification value for aggressive mode [foo]'),
    ('vid', 'comma-separated vendor IDs to use'),
    )
  available_actions = ()

  available_keys = {
    'TRANS': generate_transforms,
    }

  Response = Response_Base

  def __init__(self):
    uid = multiprocessing.current_process().name[9:]
    self.sport = '51%d' % int(uid)

  def execute(self, host, port='500', transform='5,1,1,2', aggressive='0', groupname='foo', vid=''):

    cmd = ['ike-scan', '-M', '--sport', self.sport, host, '--dport', port, '--trans', transform]
    if aggressive == '1':
      cmd.append('-A')
      if groupname:
        cmd.extend(['--id', groupname])
    for v in vid.split(','):
      cmd.extend(['--vendor', v])

    with Timing() as timing:
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = map(B, p.communicate())
      code = p.returncode

    trace = '%s\n[out]\n%s\n[err]\n%s\n' % (' '.join(cmd), out, err)
    logger.debug('trace: %r' % trace)

    has_sa = 'SA=(' in out
    if has_sa:
      mesg = 'Handshake returned: %s (%s)' % (re.search('SA=\((.+) LifeType', out).group(1), re.search('\t(.+) Mode Handshake returned', out).group(1))
    else:
      try:
        mesg = out.strip().split('\n')[1].split('\t')[-1]
      except:
        mesg = ' '.join(repr(s) for s in filter(None, [out, err]))

    resp = self.Response(code, mesg, timing, trace)
    if has_sa:
      endpoint = '%s:%s (%s Mode)' % (host, port, 'Aggressive' if aggressive == '1' else 'Main')
      resp.rrs = endpoint, transform

    return resp

# }}}

# Unzip {{{
if not which('unzip'):
  notfound.append('unzip')

class Unzip_pass:
  '''Brute-force the password of encrypted ZIP files'''

  usage_hints = [
    """%prog zipfile=file.zip password=FILE0 0=passwords.txt -x ignore:code!=0""",
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

    with Timing() as timing:
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = map(B, p.communicate())
      code = p.returncode

    mesg = out.strip()
    trace = '%s\n[out]\n%s\n[err]\n%s\n' % (' '.join(cmd), out, err)

    return self.Response(code, mesg, timing, trace)

# }}}

# Keystore {{{
if not which('keytool'):
  notfound.append('java')

class Keystore_pass:
  '''Brute-force the password of Java keystore files'''

  usage_hints = [
    """%prog keystore=keystore.jks password=FILE0 0=passwords.txt -x ignore:fgrep='password was incorrect'""",
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

    with Timing() as timing:
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
      out, err = map(B, p.communicate())
      code = p.returncode

    mesg = out.strip()
    trace = '%s\n[out]\n%s\n[err]\n%s\n' % (' '.join(cmd), out, err)

    return self.Response(code, mesg, timing, trace)

# }}}

# SQLCipher {{{
try:
  if PY3:
    from pysqlcipher3 import dbapi2 as sqlcipher
  else:
    from pysqlcipher import dbapi2 as sqlcipher
except ImportError:
  notfound.append('pysqlcipher')

class SQLCipher_pass:
  '''Brute-force the password of SQLCipher-encrypted databases'''

  usage_hints = [
    """%prog database=db.sqlite password=FILE0 0=passwords.txt -x ignore:fgrep='file is encrypted'""",
    ]

  available_options = (
    ('database', 'database files to test'),
    ('password', 'passwords to test'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, database, password):
    with sqlcipher.connect(database) as db:
      c = db.cursor()
      c.execute('PRAGMA key=%r' % password)

    try:
      c.execute('PRAGMA integrity_check')
      code, mesg = '0', 'OK'

    except sqlcipher.DatabaseError as e:
      code, mesg = '1', str(e)

    return self.Response(code, mesg)

# }}}

# Umbraco {{{
import hmac

class Umbraco_crack:
  '''Crack Umbraco HMAC-SHA1 password hashes'''

  usage_hints = (
    '''%prog hashlist=@umbraco_users.pw password=FILE0 0=passwords.txt''',
    )

  available_options = (
    ('hashlist', 'hashes to crack'),
    ('password', 'password to test'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, password, hashlist):

    p = password.encode('utf-16-le')
    h = B(b64encode(hmac.new(p, p, digestmod=hashlib.sha1).digest()))

    if h not in hashlist:
      code, mesg = 1, 'fail'
    else:
      cracked = [line.rstrip() for line in hashlist.split('\n') if h in line]
      code, mesg = 0, ' '.join(cracked)

    return self.Response(code, mesg)

# }}}

# TCP Fuzz {{{
class TCP_fuzz:
  '''Fuzz TCP services'''

  usage_hints = (
    '''%prog host=10.0.0.1 port=10000 data=RANGE0 0=hex:0x00-0xffffff''',
    )

  available_options = (
    ('host', 'target host'),
    ('port', 'target port'),
    ('timeout', 'seconds to wait for a response [10]'),
    ('ssl', 'use SSL/TLS [0|1]'),
    )
  available_actions = ()

  Response = Response_Base

  def execute(self, host, port, data='', timeout='2', ssl='0'):
    fp = socket.create_connection((host, port), int(timeout))
    if ssl != '0':
      fp = wrap_socket(fp)
    fp.send(unhexlify(data))
    #fp.send(b(data))
    with Timing() as timing:
      resp = fp.recv(1024)
    fp.close()

    code = 0
    #mesg = B(hexlify(resp))
    mesg = B(resp)

    return self.Response(code, mesg, timing)

# }}}

# Dummy Test {{{
def generate_tst():
  return ['prd', 'dev'], 2

class Dummy_test:
  '''Testing module'''

  usage_hints = (
    """%prog data=_@@_RANGE0_@@_ 0=hex:0x00-0xff -e _@@_:unhex""",
    """%prog data=RANGE0 0=int:10-0""",
    """%prog data=PROG0 0='seq -w 10 -1 0'""",
    """%prog data=PROG0 0='mp64.bin -i ?l?l?l',$(mp64.bin --combination -i ?l?l?l)""",
    )

  available_options = (
    ('data', 'data to test'),
    ('data2', 'data2 to test'),
    ('delay', 'fake random delay'),
    )
  available_actions = ()

  available_keys = {
    'TST': generate_tst,
    }

  Response = Response_Base

  def execute(self, data, data2='', delay='1'):
    code, mesg = 0, '%s / %s' % (data, data2)
    with Timing() as timing:
      sleep(random.randint(0, int(delay)*1000)/1000.0)

    return self.Response(code, mesg, timing)

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
  ('rdp_gateway', (Controller_HTTP, RDP_gateway)),
  ('ajp_fuzz', (Controller, AJP_fuzz)),
  ('pop_login', (Controller, POP_login)),
  ('pop_passd', (Controller, POP_passd)),
  ('imap_login', (Controller, IMAP_login)),
  ('ldap_login', (Controller, LDAP_login)),
  ('dcom_login', (Controller, DCOM_login)),
  ('smb_login', (Controller, SMB_login)),
  ('smb_lookupsid', (Controller, SMB_lookupsid)),
  ('rlogin_login', (Controller, Rlogin_login)),
  ('vmauthd_login', (Controller, VMauthd_login)),
  ('mssql_login', (Controller, MSSQL_login)),
  ('oracle_login', (Controller, Oracle_login)),
  ('mysql_login', (Controller, MySQL_login)),
  ('mysql_query', (Controller, MySQL_query)),
  ('rdp_login', (Controller, RDP_login)),
  ('pgsql_login', (Controller, Pgsql_login)),
  ('vnc_login', (Controller, VNC_login)),

  ('dns_forward', (Controller_DNS, DNS_forward)),
  ('dns_reverse', (Controller_DNS, DNS_reverse)),
  ('snmp_login', (Controller, SNMP_login)),
  ('ike_enum', (Controller_IKE, IKE_enum)),

  ('unzip_pass', (Controller, Unzip_pass)),
  ('keystore_pass', (Controller, Keystore_pass)),
  ('sqlcipher_pass', (Controller, SQLCipher_pass)),
  ('umbraco_crack', (Controller, Umbraco_crack)),

  ('tcp_fuzz', (Controller, TCP_fuzz)),
  ('dummy_test', (Controller, Dummy_test)),
  ]

dependencies = {
  'paramiko': [('ssh_login',), 'http://www.paramiko.org/', '2.7.1'],
  'pycurl': [('http_fuzz', 'rdp_gateway'), 'http://pycurl.io/', '7.43.0'],
  'libcurl': [('http_fuzz', 'rdp_gateway'), 'https://curl.haxx.se/', '7.58.0'],
  'ajpy': [('ajp_fuzz',), 'https://github.com/hypn0s/AJPy/', '0.0.4'],
  'openldap': [('ldap_login',), 'http://www.openldap.org/', '2.4.45'],
  'impacket': [('smb_login', 'smb_lookupsid', 'dcom_login', 'mssql_login'), 'https://github.com/CoreSecurity/impacket', '0.9.20'],
  'pyopenssl': [('mssql_login',), 'https://pyopenssl.org/', '19.1.0'],
  'cx_Oracle': [('oracle_login',), 'http://cx-oracle.sourceforge.net/', '7.3.0'],
  'mysqlclient': [('mysql_login',), 'https://github.com/PyMySQL/mysqlclient-python', '1.4.6'],
  'xfreerdp': [('rdp_login',), 'https://github.com/FreeRDP/FreeRDP.git', '1.2.0-beta1'],
  'psycopg': [('pgsql_login',), 'http://initd.org/psycopg/', '2.8.4'],
  'pycrypto': [('smb_login', 'smb_lookupsid', 'mssql_login', 'vnc_login',), 'http://www.dlitz.net/software/pycrypto/', '2.6.1'],
  'dnspython': [('dns_reverse', 'dns_forward'), 'http://www.dnspython.org/', '1.16.0'],
  'IPy': [('dns_reverse', 'dns_forward'), 'https://github.com/haypo/python-ipy', '1.0'],
  'pysnmp': [('snmp_login',), 'http://pysnmp.sf.net/', '4.4.12'],
  'pyasn1': [('smb_login', 'smb_lookupsid', 'mssql_login', 'snmp_login'), 'http://sourceforge.net/projects/pyasn1/', '0.4.8'],
  'ike-scan': [('ike_enum',), 'http://www.nta-monitor.com/tools-resources/security-tools/ike-scan', '1.9'],
  'unzip': [('unzip_pass',), 'http://www.info-zip.org/', '6.0'],
  'java': [('keystore_pass',), 'http://www.oracle.com/technetwork/java/javase/', '6'],
  'pysqlcipher': [('sqlcipher_pass',), 'https://github.com/rigglemania/pysqlcipher3', '1.0.3'],
  'python': [('ftp_login',), 'Patator requires Python 3.6 or above and may still work on Python 2.'],
  }

# }}}

# main {{{
if __name__ == '__main__':
  multiprocessing.freeze_support()

  def show_usage():
    print(__banner__)
    print('''Usage: patator.py module --help

Available modules:
%s''' % '\n'.join('  + %-13s : %s' % (k, v[1].__doc__) for k, v in modules))

    sys.exit(2)

  available = dict(modules)
  name = os.path.basename(sys.argv[0]).lower()

  if name not in available:
    if len(sys.argv) == 1:
      show_usage()

    name = os.path.basename(sys.argv[1]).lower()
    if name not in available:
      show_usage()

    del sys.argv[0]

  # dependencies
  abort = False
  for k in set(notfound):
    args = dependencies[k]
    if name in args[0]:
      if len(args) == 2:
        print('WARNING: %s' % args[1])
      else:
        url, ver = args[1:]
        print('ERROR: %s %s (%s) is required to run %s.' % (k, ver, url, name))
        abort = True

  if abort:
    print('Please read the README inside for more information.')
    sys.exit(3)

  # start
  ctrl, module = available[name]
  powder = ctrl(module, [name] + sys.argv[1:])
  powder.fire()

# }}}

# vim: ts=2 sw=2 sts=2 et fdm=marker bg=dark
