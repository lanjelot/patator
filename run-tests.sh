#!/bin/bash

if ! type docker-compose &>/dev/null; then
  echo 'docker-compose is required'
  exit 1
fi

case "$1" in
  python2|python3)
    PYTHON=$1
    ;;
  *)
    docker-compose up -d --build

    $0 python3
    $0 python2

    exit 0
  ;;
esac

UNIX='unix'
ORACLE='oracle'
MSSQL='mssql'
WIN10='' # vagrant add senglin/win-7-enterprise
VPN=''   #

LOGS='-l ./asdf -y --hits ./hits.txt'

run()
{
  echo
  echo "$ $@"
  docker-compose run --no-deps --rm --entrypoint "$PYTHON patator.py" patator "$@"
}

echo
echo ">>> $PYTHON"

run ftp_login host=$UNIX
run ftp_login host=$UNIX user=userRANGE0 password=PasswordRANGE0 0=int:0-9

run ssh_login host=$UNIX
run ssh_login host=$UNIX user=userRANGE0 password=PasswordRANGE0 0=int:0-9

run telnet_login host=$UNIX
run telnet_login host=$UNIX inputs='userRANGE0\nPasswordRANGE0' 0=int:0-9 prompt_re='login:|Password:' timeout=5

run smtp_vrfy host=$UNIX
run smtp_vrfy host=$UNIX user=userRANGE0 0=int:1-500 -x ignore:fgrep='User unknown' -x ignore,reset,retry:code=421 --auto-progress 10

run smtp_rcpt host=$UNIX
run smtp_rcpt host=$UNIX mail_from=root@localhost user=userRANGE0@localhost 0=int:1-200 -x ignore:fgrep='User unknown'

run smtp_login host=$UNIX
run smtp_login host=$UNIX user=userRANGE0 password=PasswordRANGE0 0=int:0-30 starttls=1 #-x ignore,reset,retry:code=421

run finger_lookup host=$UNIX
run finger_lookup host=$UNIX user=userRANGE0 0=int:0-20 -x ignore:fgrep='no such user'

run ldap_login host=$UNIX
run ldap_login host=$UNIX binddn='cn=admin,dc=example,dc=com' bindpw=PasswordRANGE0 0=int:0-9 basedn='dc=example,dc=com'

run smb_login host=$UNIX
run smb_login host=$UNIX user=userRANGE0 password=PasswordRANGE0 0=int:0-9

if [[ ! -z $WIN10 ]]; then
  run smb_login host=$WIN10 user=vagranRANGE0 password=vagranRANGE0 0=lower:r-v
  run smb_lookupsid host=$WIN10 user=vagrant password=vagrant rid=RANGE0 0=int:500-2000 -x ignore:code=1
  run dcom_login host=$WIN10 user=vagranRANGE0 password=vagranRANGE0 0=lower:r-v

  xhost +si:localuser:root
    run rdp_login host=$WIN10 user=vagranRANGE0 password=vagranRANGE0 0=lower:r-v
  xhost -si:localuser:root
fi

run pop_login host=$UNIX
run pop_login host=$UNIX user=userRANGE0 password=PasswordRANGE0 0=int:0-9

run pop_passd host=$UNIX
run pop_passd host=$UNIX user=userRANGE0 password=PasswordRANGE0 0=int:0-9

run imap_login host=$UNIX
run imap_login host=$UNIX user=userRANGE0 password=PasswordRANGE0 0=int:0-9

run rlogin_login host=$UNIX user=userRANGE0 password=PasswordRANGE0 0=int:0-9

run mysql_login host=$UNIX
run mysql_login host=$UNIX user=root password=PasswordRANGE0 0=int:0-9

run mysql_query host=$UNIX user=root password=Password1 query='select host, user from mysql.user'
run mysql_query host=$UNIX user=root password=Password1 query='select load_file("/etc/hosts")'

run mssql_login host=$MSSQL user=sa password=PasswordRANGE0 0=int:0-9

run oracle_login host=$ORACLE sid=xRANGE0 0=lower:a-f -t 1
run oracle_login host=$ORACLE sid=xe user=sys password=oraclRANGE0 0=lower:a-f

run pgsql_login host=$UNIX
run pgsql_login host=$UNIX user=postgres password=PasswordRANGE0 0=int:0-9

run http_fuzz url="http://$UNIX/RANGE0" 0=lower:a-zzz -x ignore:code=404
run http_fuzz url=http://$UNIX:8080/manager/html user_pass=tomcat:PasswordRANGE0 0=int:0-9

run ajp_fuzz url=ajp://$UNIX/manager/html user_pass=tomcat:PasswordRANGE0 0=int:0-9

run vnc_login host=$UNIX port=5900 password=PassworRANGE0 0=lower:a-f

run dns_reverse host=NET0 0=216.239.32.0-216.239.32.255,8.8.8.0/24 -x ignore:code=3 -x ignore:fgrep!=google.com -x ignore:fgrep=216-239-
run dns_forward name=MOD0.microsoft.com 0=SRV qtype=SRV -x ignore:code=3 --auto-progress 15

run snmp_login host=$UNIX community=publiRANGE0 0=lower:a-f
run snmp_login host=$UNIX community=public version=3 user=userRANGE0 0=int:0-5 auth_key=whatever
run snmp_login host=$UNIX community=public version=3 user=user3 auth_proto=sha auth_key=authPasRANGE0 0=lower:q-v
run snmp_login host=$UNIX community=public version=3 user=user3 auth_proto=sha auth_key=authPass priv_proto=aes priv_key=privPasRANGE0 0=lower:q-v

if [[ ! -z $VPN ]]; then
  run ike_enum host=$VPN transform=MOD0 0=TRANS aggressive=RANGE1 1=int:0-1 -x ignore:fgrep=NO-PROPOSAL
fi

run unzip_pass zipfile=enc.zip password=PasswordRANGE0 0=int:0-9
run keystore_pass keystore=keystore.jks password=PasswordRANGE0 0=int:0-9
run sqlcipher_pass database=enc.db password=PasswordRANGE0 0=int:0-9
run umbraco_crack hashlist=@umbraco_users.pw password=PasswordRANGE0 0=int:0-9

run tcp_fuzz host=$UNIX port=4444 data=RANGE0 0=hex:0xf0-0xf9 # $LOGS

echo -e '\xde\xad\xbe\xef\nprintable ascii' > dummy.txt
run dummy_test delay=0 data=FILE0 0=dummy.txt data2=RANGE1 1=lower:a-b

echo -e 'wrong pass\np\x1fssw\x09rd' > user9.pass
run ssh_login host=unix user=user9 password=FILE0 0=user9.pass

rm -f dummy.txt user9.pass
