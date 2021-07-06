# Patator

Patator was written out of frustration from using Hydra, Medusa, Ncrack, Metasploit modules and Nmap NSE scripts for password guessing attacks. I opted for a different approach in order to not create yet another brute-forcing tool and avoid repeating the same shortcomings. Patator is a multi-threaded tool written in Python, that strives to be more reliable and flexible than his fellow predecessors.

Currently it supports the following modules:

```
* ftp_login      : Brute-force FTP
* ssh_login      : Brute-force SSH
* telnet_login   : Brute-force Telnet
* smtp_login     : Brute-force SMTP
* smtp_vrfy      : Enumerate valid users using the SMTP VRFY command
* smtp_rcpt      : Enumerate valid users using the SMTP RCPT TO command
* finger_lookup  : Enumerate valid users using Finger
* http_fuzz      : Brute-force HTTP/HTTPS
* rdp_gateway    : Brute-force RDP Gateway
* ajp_fuzz       : Brute-force AJP
* pop_login      : Brute-force POP
* pop_passd      : Brute-force poppassd (not POP3)
* imap_login     : Brute-force IMAP
* ldap_login     : Brute-force LDAP
* dcom_login     : Brute-force DCOM
* smb_login      : Brute-force SMB
* smb_lookupsid  : Brute-force SMB SID-lookup
* rlogin_login   : Brute-force rlogin
* vmauthd_login  : Brute-force VMware Authentication Daemon
* mssql_login    : Brute-force MSSQL
* oracle_login   : Brute-force Oracle
* mysql_login    : Brute-force MySQL
* mysql_query    : Brute-force MySQL queries
* rdp_login      : Brute-force RDP (NLA)
* pgsql_login    : Brute-force PostgreSQL
* vnc_login      : Brute-force VNC
* dns_forward    : Brute-force DNS
* dns_reverse    : Brute-force DNS (reverse lookup subnets)
* ike_enum       : Enumerate IKE transforms
* snmp_login     : Brute-force SNMPv1/2 and SNMPv3
* unzip_pass     : Brute-force the password of encrypted ZIP files
* keystore_pass  : Brute-force the password of Java keystore files
* sqlcipher_pass : Brute-force the password of SQLCipher-encrypted databases
* umbraco_crack  : Crack Umbraco HMAC-SHA1 password hashes
```

The name "Patator" comes from [this](https://www.youtube.com/watch?v=9sF9fTALhVA).

Patator is NOT script-kiddie friendly, please read the full README inside [patator.py](patator.py) before reporting.

Please donate if you like this project! :)

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=SB36VJH4EM5WG&lc=AU&item_name=lanjelot&item_number=patator&currency_code=AUD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)

Many thanks! [@lanjelot](https://twitter.com/lanjelot)

## Install

```
git clone https://github.com/lanjelot/patator.git
git clone https://github.com/danielmiessler/SecLists.git
docker build -t patator patator/
docker run -it --rm -v $PWD/SecLists/Passwords:/mnt patator dummy_test data=FILE0 0=/mnt/richelieu-french-top5000.txt
```

## Usage Examples

* FTP : Enumerating users denied login in `vsftpd/userlist`

```
$ ftp_login host=10.0.0.1 user=FILE0 0=logins.txt password=asdf -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500
19:36:06 patator    INFO - Starting Patator v0.7-beta (https://github.com/lanjelot/patator) at 2015-02-08 19:36 AEDT
19:36:06 patator    INFO -
19:36:06 patator    INFO - code  size    time | candidate                          |   num | mesg
19:36:06 patator    INFO - -----------------------------------------------------------------------------
19:36:07 patator    INFO - 230   17     0.002 | anonymous                          |     7 | Login successful.
19:36:07 patator    INFO - 230   17     0.001 | ftp                                |    10 | Login successful.
19:36:08 patator    INFO - 530   18     1.000 | root                               |     1 | Permission denied.
19:36:17 patator    INFO - 530   18     1.000 | michael                            |    50 | Permission denied.
19:36:36 patator    INFO - 530   18     1.000 | robert                             |    93 | Permission denied.
...
```

Tested against `vsftpd-3.0.2-9` on `CentOS 7.0-1406`.

* SSH : Time-based user enumeration

```
$ ssh_login host=10.0.0.1 user=FILE0 0=logins.txt password=$(perl -e "print 'A'x50000") --max-retries 0 --timeout 10 -x ignore:time=0-3
17:45:20 patator    INFO - Starting Patator v0.7-beta (https://github.com/lanjelot/patator) at 2015-02-08 17:45 AEDT
17:45:20 patator    INFO -
17:45:20 patator    INFO - code  size    time | candidate                          |   num | mesg
17:45:20 patator    INFO - -----------------------------------------------------------------------------
17:45:30 patator    FAIL - xxx   41    10.001 | root                               |     1 | <class '__main__.TimeoutError'> timed out
17:45:34 patator    FAIL - xxx   41    10.000 | john                               |    23 | <class '__main__.TimeoutError'> timed out
17:45:37 patator    FAIL - xxx   41    10.000 | joe                                |    40 | <class '__main__.TimeoutError'> timed out
...
```

Tested against `openssh-server 1:6.0p1-4+deb7u2` on `Debian 7.8`.

* HTTP : Brute-force phpMyAdmin logon

```
$ http_fuzz url=http://10.0.0.1/pma/index.php method=POST body='pma_username=COMBO00&pma_password=COMBO01&server=1&target=index.php&lang=en&token=' 0=combos.txt before_urls=http://10.0.0.1/pma/index.php accept_cookie=1 follow=1 -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf
11:53:47 patator    INFO - Starting Patator v0.7-beta (http://code.google.com/p/patator/) at 2014-08-31 11:53 EST
11:53:47 patator    INFO -
11:53:47 patator    INFO - code size:clen       time | candidate                          |   num | mesg
11:53:47 patator    INFO - -----------------------------------------------------------------------------
11:53:48 patator    INFO - 200  49585:0        0.150 | root:p@ssw0rd                      |    26 | HTTP/1.1 200 OK
11:53:51 patator    INFO - 200  13215:0        0.351 | root:                              |    72 | HTTP/1.1 200 OK
^C
11:53:54 patator    INFO - Hits/Done/Skip/Fail/Size: 2/198/0/0/3000, Avg: 29 r/s, Time: 0h 0m 6s
11:53:54 patator    INFO - To resume execution, pass --resume 15,15,15,16,15,36,15,16,15,40
```

Payload #72 was a false positive due to an unexpected error message:

```
$ grep AllowNoPassword /tmp/qsdf/72_200\:13215\:0\:0.351.txt
... class="icon ic_s_error" /> Login without a password is forbidden by configuration (see AllowNoPassword)</div><noscript>
```

Tested against `phpMyAdmin 4.2.7.1`.

* IKEv1 : Enumerate transforms supported by VPN peer

```
# ike_enum host=10.0.0.1 transform=MOD0 0=TRANS aggressive=RANGE1 1=int:0-1 -x ignore:fgrep='NO-PROPOSAL'
16:52:58 patator    INFO - Starting Patator v0.7-beta (https://github.com/lanjelot/patator) at 2015-04-05 16:52 AEST
16:52:58 patator    INFO -
16:52:58 patator    INFO - code  size    time | candidate                          |   num | mesg
16:52:58 patator    INFO - -----------------------------------------------------------------------------
16:53:03 patator    INFO - 0     70     0.034 | 5,1,1,2:0                          |  1539 | Handshake returned: Enc=3DES Hash=MD5 Group=2:modp1024 Auth=PSK (Main)
16:53:03 patator    INFO - 0     72     0.031 | 5,1,65001,2:0                      |  1579 | Handshake returned: Enc=3DES Hash=MD5 Group=2:modp1024 Auth=XAUTH&PSK (Main)
16:53:03 patator    INFO - 0     76     0.033 | 5,1,1,2:1                          |  1540 | Handshake returned: Enc=3DES Hash=MD5 Group=2:modp1024 Auth=PSK (Aggressive)
16:53:03 patator    INFO - 0     78     0.034 | 5,1,65001,2:1                      |  1580 | Handshake returned: Enc=3DES Hash=MD5 Group=2:modp1024 Auth=XAUTH&PSK (Aggressive)
16:53:06 patator    INFO - 0     84     0.034 | 7/128,2,1,2:0                      |  2371 | Handshake returned: Enc=AES KeyLength=128 Hash=SHA1 Group=2:modp1024 Auth=PSK (Main)
16:53:06 patator    INFO - 0     90     0.033 | 7/128,2,1,2:1                      |  2372 | Handshake returned: Enc=AES KeyLength=128 Hash=SHA1 Group=2:modp1024 Auth=PSK (Aggressive)
16:53:06 patator    INFO - 0     86     0.034 | 7/128,2,65001,2:0                  |  2411 | Handshake returned: Enc=AES KeyLength=128 Hash=SHA1 Group=2:modp1024 Auth=XAUTH&PSK (Main)
16:53:06 patator    INFO - 0     92     0.035 | 7/128,2,65001,2:1                  |  2412 | Handshake returned: Enc=AES KeyLength=128 Hash=SHA1 Group=2:modp1024 Auth=XAUTH&PSK (Aggressive)

+ 10.0.0.1:500 (Main Mode)
    Encryption       Hash             Auth       Group
    ---------- ----------       ----------  ----------
          3DES        MD5              PSK    modp1024
          3DES        MD5        XAUTH&PSK    modp1024
        AES128       SHA1              PSK    modp1024
        AES128       SHA1        XAUTH&PSK    modp1024

+ 10.0.0.1:500 (Aggressive Mode)
    Encryption       Hash             Auth       Group
    ---------- ----------       ----------  ----------
          3DES        MD5              PSK    modp1024
          3DES        MD5        XAUTH&PSK    modp1024
        AES128       SHA1              PSK    modp1024
        AES128       SHA1        XAUTH&PSK    modp1024
16:53:11 patator    INFO - Hits/Done/Skip/Fail/Size: 8/3840/0/0/3840, Avg: 284 r/s, Time: 0h 0m 13s
```

* SNMPv3 : Find valid usernames

```
$ snmp_login host=10.0.0.1 version=3 user=FILE0 0=logins.txt -x ignore:mesg=unknownUserName
17:51:06 patator    INFO - Starting Patator v0.5
17:51:06 patator    INFO -
17:51:06 patator    INFO - code  size | candidate                          |   num | mesg
17:51:06 patator    INFO - ----------------------------------------------------------------------
17:51:11 patator    INFO - 0-0   11   | robert                             |    55 | wrongDigest
17:51:12 patator    INFO - Progress:  20% (70/345) | Speed: 10 r/s | ETC: 17:51:38 (00:00:26 remaining)
17:51:33 patator    INFO - 0-0   11   | myuser                             |   311 | wrongDigest
17:51:36 patator    INFO - Hits/Done/Skip/Fail/Size: 2/345/0/0/345, Avg: 11 r/s, Time: 0h 0m 30s
```

* SNMPv3 : Find valid passwords

```
$ snmp_login host=10.0.0.1 version=3 user=robert auth_key=FILE0 0=passwords_8+.txt -x ignore:mesg=wrongDigest
17:52:15 patator    INFO - Starting Patator v0.5
17:52:15 patator    INFO -
17:52:15 patator    INFO - code  size | candidate                          |   num | mesg
17:52:15 patator    INFO - ----------------------------------------------------------------------
17:52:16 patator    INFO - 0-0   69   | password123                        |    16 | Linux thug 2.6.36-gentoo #5 SMP Fri Aug 12 14:49:51 CEST 2011 i686
17:52:17 patator    INFO - Hits/Done/Skip/Fail/Size: 1/50/0/0/50, Avg: 38 r/s, Time: 0h 0m 1s
```

* DNS : Forward lookup

```
$ dns_forward name=FILE0.hsc.fr 0=names.txt -x ignore:code=3
03:18:46 patator    INFO - Starting Patator v0.5 (http://code.google.com/p/patator/) at 2012-06-29 03:18 PMT
03:18:46 patator    INFO -
03:18:46 patator    INFO - code  size | candidate                          |   num | mesg
03:18:46 patator    INFO - ----------------------------------------------------------------------
03:18:46 patator    INFO - 0     41   | www                                |     4 | NOERROR [www.hsc.fr. IN A 217.174.211.25]
03:18:46 patator    INFO - 0     81   | mail                               |    32 | NOERROR [mail.hsc.fr. IN CNAME itesec.hsc.fr.][itesec.hsc.fr. IN A 192.70.106.33]
03:18:46 patator    INFO - 0     44   | webmail                            |    62 | NOERROR [webmail.hsc.fr. IN A 192.70.106.95]
03:18:46 patator    INFO - 0     93   | test                               |    54 | NOERROR [hsc.fr. IN SOA itesec.hsc.fr. hostmaster.hsc.fr. 2012012301 21600 3600 1209600 3600]
03:18:46 patator    INFO - 0     40   | wap                                |    66 | NOERROR [wap.hsc.fr. IN A 192.70.106.33]
03:18:46 patator    INFO - 0     85   | extranet                           |   131 | NOERROR [extranet.hsc.fr. IN CNAME itesec.hsc.fr.][itesec.hsc.fr. IN A 192.70.106.33]
03:18:46 patator    INFO - 0     81   | news                               |   114 | NOERROR [news.hsc.fr. IN CNAME itesec.hsc.fr.][itesec.hsc.fr. IN A 192.70.106.33]
03:18:46 patator    INFO - 0     93   | mailhost                           |   137 | NOERROR [mailhost.hsc.fr. IN A 192.70.106.33][mailhost.hsc.fr. IN AAAA 2001:7a8:1155:2::abcd]
03:18:46 patator    INFO - 0     47   | lists                              |   338 | NOERROR [lists.hsc.fr. IN MX 10 itesec.hsc.fr.]
03:18:46 patator    INFO - 0     93   | fr                                 |   319 | NOERROR [hsc.fr. IN SOA itesec.hsc.fr. hostmaster.hsc.fr. 2012012301 21600 3600 1209600 3600]
03:18:47 patator    INFO - 0     40   | gl                                 |   586 | NOERROR [gl.hsc.fr. IN A 192.70.106.103]
Records ------------------------------------------
                  extranet.hsc.fr.   IN CNAME   itesec.hsc.fr.
                        gl.hsc.fr.   IN A       192.70.106.103
                           hsc.fr.   IN SOA     itesec.hsc.fr. hostmaster.hsc.fr. 2012012301 21600 3600 1209600 3600
                    itesec.hsc.fr.   IN A       192.70.106.33
                     lists.hsc.fr.   IN MX      10 itesec.hsc.fr.
                      mail.hsc.fr.   IN CNAME   itesec.hsc.fr.
                  mailhost.hsc.fr.   IN A       192.70.106.33
                  mailhost.hsc.fr.   IN AAAA    2001:7a8:1155:2::abcd
                      news.hsc.fr.   IN CNAME   itesec.hsc.fr.
                       wap.hsc.fr.   IN A       192.70.106.33
                   webmail.hsc.fr.   IN A       192.70.106.95
                       www.hsc.fr.   IN A       217.174.211.25
Hostmap ------------------------------------------
                   mailhost.hsc.fr 2001:7a8:1155:2::abcd
                   mailhost.hsc.fr 192.70.106.33
                        wap.hsc.fr 192.70.106.33
                     itesec.hsc.fr 192.70.106.33
                   extranet.hsc.fr
                       mail.hsc.fr
                       news.hsc.fr
                    webmail.hsc.fr 192.70.106.95
                         gl.hsc.fr 192.70.106.103
                        www.hsc.fr 217.174.211.25
Domains ------------------------------------------
                            hsc.fr 10
Networks -----------------------------------------
                                   2001:7a8:1155:2::abcd
                                   192.70.106.x
                                   217.174.211.25
03:18:53 patator    INFO - Hits/Done/Skip/Fail/Size: 11/1000/0/0/1000, Avg: 133 r/s, Time: 0h 0m 7s
```

Also notice that `test.hsc.fr.` is the start of a new zone because we got NOERROR and no IP address.

* DNS : Reverse lookup two netblocks owned by Google

```
$ dns_reverse host=NET0 0=216.239.32.0-216.239.47.255,8.8.8.0/24 -x ignore:code=3 -x ignore:fgrep!=google.com -x ignore:fgrep=216-239-
03:24:22 patator    INFO - Starting Patator v0.5 (http://code.google.com/p/patator/) at 2012-06-29 03:24 PMT
03:24:22 patator    INFO -
03:24:22 patator    INFO - code  size | candidate                          |   num | mesg
03:24:22 patator    INFO - ----------------------------------------------------------------------
03:24:22 patator    INFO - 0     46   | 216.239.32.10                      |    11 | NOERROR [216.239.32.10 IN PTR ns1.google.com.]
03:24:22 patator    INFO - 0     45   | 216.239.32.11                      |    12 | NOERROR [216.239.32.11 IN PTR ns.google.com.]
03:24:22 patator    INFO - 0     48   | 216.239.32.15                      |    16 | NOERROR [216.239.32.15 IN PTR time1.google.com.]
03:24:23 patator    INFO - 0     47   | 216.239.33.5                       |   262 | NOERROR [216.239.33.5 IN PTR proxy.google.com.]
03:24:23 patator    INFO - 0     47   | 216.239.33.12                      |   269 | NOERROR [216.239.33.12 IN PTR dns1.google.com.]
03:24:23 patator    INFO - 0     51   | 216.239.33.22                      |   279 | NOERROR [216.239.33.22 IN PTR transfer.google.com.]
03:24:23 patator    INFO - 0     50   | 216.239.33.20                      |   277 | NOERROR [216.239.33.20 IN PTR esc-out.google.com.]
03:24:23 patator    INFO - 0     46   | 216.239.34.10                      |   523 | NOERROR [216.239.34.10 IN PTR ns2.google.com.]
03:24:23 patator    INFO - 0     48   | 216.239.34.15                      |   528 | NOERROR [216.239.34.15 IN PTR time2.google.com.]
^C
Records ------------------------------------------
                     216.239.32.10       IN PTR      ns1.google.com.
                     216.239.32.11       IN PTR      ns.google.com.
                     216.239.32.15       IN PTR      time1.google.com.
                     216.239.33.12       IN PTR      dns1.google.com.
                     216.239.33.20       IN PTR      esc-out.google.com.
                     216.239.33.22       IN PTR      transfer.google.com.
                      216.239.33.5       IN PTR      proxy.google.com.
                     216.239.34.10       IN PTR      ns2.google.com.
                     216.239.34.15       IN PTR      time2.google.com.
Hostmap ------------------------------------------
                    ns1.google.com 216.239.32.10
                     ns.google.com 216.239.32.11
                  time1.google.com 216.239.32.15
                  proxy.google.com 216.239.33.5
                   dns1.google.com 216.239.33.12
                esc-out.google.com 216.239.33.20
               transfer.google.com 216.239.33.22
                    ns2.google.com 216.239.34.10
                  time2.google.com 216.239.34.15
Domains ------------------------------------------
                        google.com 9
Networks -----------------------------------------
                                   216.239.32.x
                                   216.239.33.x
                                   216.239.34.x
03:24:29 patator    INFO - Hits/Done/Skip/Fail/Size: 9/872/0/0/4352, Avg: 115 r/s, Time: 0h 0m 7s
03:24:29 patator    INFO - To resume execution, pass --resume 91,75,93,73,84,95,94,95,83,89
```

* ZIP : Crack a password-protected ZIP file (older pkzip encryption used not to be supported in JtR)

```
$ unzip_pass zipfile=challenge1.zip password=FILE0 0=rockyou.dic -x ignore:code!=0
10:54:29 patator    INFO - Starting Patator v0.5 (http://code.google.com/p/patator/) at 2012-06-29 10:54:29 PMT
10:54:29 patator    INFO -
10:54:29 patator    INFO - code  size | candidate                          |   num | mesg
10:54:29 patator    INFO - ----------------------------------------------------------------------
10:54:30 patator    INFO - 0     82   | love                               |   387 | 0 [82] No errors detected in compressed data of challenge1.zip.
^C
10:54:31 patator    INFO - Hits/Done/Skip/Fail/Size: 1/1589/0/0/5000, Avg: 699 r/s, Time: 0h 0m 2s
10:54:31 patator    INFO - To resume execution, pass --resume 166,164,165,166,155,158,148,158,155,154
```

## PyInstaller
### Bundling on Windows 5.2.3790 x86

Install `python-2.7.9.msi` from [Python](https://www.python.org/downloads/windows/).
Install `pywin32-219.win32-py2.7.exe` from [PyWin32](http://sourceforge.net/projects/pywin32/files/pywin32/).
Install `vcredist_x86.exe` from [Microsoft](http://www.microsoft.com/en-us/download/confirmation.aspx?id=29).
Install `Git-1.9.5.exe` from [Git](http://git-scm.com/download/win) (and select "Use Git from Windows Command Prompt" during install).
Add `c:\Python27;c:\Python27\Scripts` to your `PATH`.

```
pip install pycrypto pyopenssl
pip install impacket
pip install paramiko
pip install IPy
pip install dnspython
pip install pysnmp

cd c:\
git clone https://github.com/lanjelot/patator
git clone https://github.com/pyinstaller/pyinstaller
cd pyinstaller
git checkout a2b0617251ebe70412f6e3573f00a49ce08b7b32 # fixes this issue: https://groups.google.com/forum/#!topic/pyinstaller/6xD75_w4F-c
python pyinstaller.py --clean --onefile c:\patator\patator.py
patator\dist\patator.exe -h
```

The resulting stand-alone `patator.exe` executable was confirmed to run successfully on Windows 2003 (5.2.3790), Windows 7 (6.1.7600), Windows 2008 R2 SP1 (6.1.7601) and Windows 2012 R2 (6.3.9600), and is likely to work fine on other Windows versions.

Refer to [#50](https://github.com/lanjelot/patator/issues/50) for more info.
