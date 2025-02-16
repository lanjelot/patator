FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN { for i in {3..5}; do useradd -m -s /bin/bash user$i; echo -e "Password$i\nPassword$i" | passwd user$i; done; } \
 && useradd -m user9 && echo -e 'p\x1fssw\x09rd\np\x1fssw\x09rd' | passwd user9

# utils
RUN sed -i 's:^path-exclude=/usr/share/man:#path-exclude=/usr/share/man:' /etc/dpkg/dpkg.cfg.d/excludes \
  && apt-get update \
  && apt-get install -y --no-install-recommends man manpages-posix iproute2 mlocate lsof sudo vim less telnet finger rsh-client smbclient \
  && rm -rf /var/lib/apt/lists/* \
  && echo 'set bg=dark' > /root/.vimrc \
  && usermod -aG sudo user3

# services
RUN apt-get update \
  && apt-get install -y --no-install-recommends vsftpd openssh-server telnetd rsh-redone-server fingerd apache2 socat \
  && rm -rf /var/lib/apt/lists/* \
  && echo 'background=YES' >> /etc/vsftpd.conf \
  && sed -i -e 's,start-stop-daemon --start --background,start-stop-daemon --start,' /etc/init.d/vsftpd

RUN { echo "postfix postfix/mailname string ubuntu-blah"; \
      echo "postfix postfix/main_mailer_type string 'Internet Site'"; \
    } | debconf-set-selections \
  && apt-get update && apt-get install -y --no-install-recommends postfix dovecot-pop3d dovecot-imapd \
  && rm -rf /var/lib/apt/lists/* \
  && postconf 'smtpd_sasl_exceptions_networks=' 'smtpd_sasl_auth_enable=yes' 'smtpd_sasl_type=dovecot' 'smtpd_sasl_path=private/dovecot-auth' \
  && echo -e 'auth_mechanisms = plain login\n\
service auth {\n\
  unix_listener /var/spool/postfix/private/dovecot-auth {\n\
    mode = 0660\n\
    user = postfix\n\
    group = postfix\n\
  }\n\
}\n' > /etc/dovecot/conf.d/99-blah.conf

RUN echo 'ServerName localhost' >> /etc/apache2/apache2.conf \
  && mkdir /var/www/html/{wp,pma,bak} && echo secret > /var/www/html/key

RUN LDAPPW=Password1; \
  { \
    echo slapd slapd/internal/generated_adminpw password $LDAPPW; \
    echo slapd slapd/password2 password $LDAPPW; \
    echo slapd slapd/internal/adminpw password $LDAPPW; \
    echo slapd slapd/password1 password $LDAPPW; \
    echo slapd slapd/domain string example.com; \
    echo slapd shared/organization string example.com;  \
  } | debconf-set-selections \
  && apt-get update && apt-get install -y --no-install-recommends slapd ldap-utils \
  && rm -rf /var/lib/apt/lists/*

RUN MYSRP=Password1; \
  { echo "mysql-server mysql-server/root_password password $MYSRP"; \
    echo "mysql-server mysql-server/root_password_again password $MYSRP"; \
  } | debconf-set-selections \
  && apt-get update && apt-get install -y --no-install-recommends mysql-server \
  && rm -rf /var/lib/apt/lists/* \
  && sed -i "s/bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf \
  && echo secure_file_priv= >> /etc/mysql/mysql.conf.d/mysqld.cnf \
  && rm -f /etc/apparmor.d/usr.sbin.mysqld \
  && service mysql start \
  && Q1="CREATE USER 'root'@'%' identified by 'Password1';" \
  && Q2="GRANT ALL PRIVILEGES ON *.* TO 'root'@'%';" \
  && Q3="FLUSH PRIVILEGES;" \
  && SQL="${Q1}${Q2}${Q3}" \
  && mysql -uroot -p"$MYSRP" -e "$SQL"

RUN PGPW=Password1 \
  && apt-get update && apt-get install -y --no-install-recommends postgresql \
  && rm -rf /var/lib/apt/lists/* \
  && sed -ie 's,127.0.0.1/32,0.0.0.0/0,' /etc/postgresql/14/main/pg_hba.conf \
  && sed -ie "s,^#listen_addresses = 'localhost',listen_addresses = '*'," /etc/postgresql/14/main/postgresql.conf \
  && service postgresql start \
  && su - postgres -c "psql -c \"ALTER USER postgres WITH PASSWORD '$PGPW';\" -c '\\q'" \
  && su - postgres -c "PGPASSWORD='$PGPW' psql -d postgres -w --no-password -h localhost -p 5432 -t -c 'SELECT version()'"

RUN apt-get update && apt-get install -y --no-install-recommends tomcat9 tomcat9-admin \
  && rm -rf /var/lib/apt/lists/* \
  && echo '<?xml version="1.0" encoding="UTF-8"?><tomcat-users xmlns="http://tomcat.apache.org/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd" version="1.0"><user username="tomcat" password="Password1" roles="manager-gui"/></tomcat-users>' > /etc/tomcat9/tomcat-users.xml \
  && sed -ie 's,^.*Define an AJP .* Connector on port.*$,<Connector protocol="AJP/1.3" address="0.0.0.0" port="8009" redirectPort="8443" secretRequired="false"/>,' /etc/tomcat9/server.xml \
  && sed -ie 's,catalina.realm.LockOutRealm",catalina.realm.LockOutRealm" lockOutTime="0",' /etc/tomcat9/server.xml \
  && echo -e "#!/bin/sh\n\
export CATALINA_HOME=/usr/share/tomcat9\n\
export CATALINA_BASE=/var/lib/tomcat9\n\
export CATALINA_TMPDIR=/tmp\n\
export SECURITY_MANAGER=true\n\
export JAVA_OPTS=-Djava.awt.headless=true\n\
/usr/libexec/tomcat9/tomcat-update-policy.sh\n\
/usr/libexec/tomcat9/tomcat-start.sh &\n" > /usr/local/sbin/start-tomcat.sh

RUN apt-get update && apt-get install -y --no-install-recommends dovecot-imapd dovecot-pop3d poppassd \
  && rm -rf /var/lib/apt/lists/* \
  && sed -ie 's,^#login_trusted_networks = *$,login_trusted_networks = 0.0.0.0/0,' /etc/dovecot/dovecot.conf

RUN apt-get update && apt-get install -y --no-install-recommends p7zip-full \
  && rm -rf /var/lib/apt/lists/* \
 && 7za a -pPassword1 /root/enc.zip /etc/passwd

RUN apt-get update && apt-get install -y --no-install-recommends openjdk-18-jre-headless \
  && rm -rf /var/lib/apt/lists/* \
  && keytool -genkey -alias test -storepass Password1 -keypass Password1 -keystore /root/keystore.jks -dname "CN=a,OU=b,O=c,L=d,ST=e,C=f" -keyalg RSA

RUN apt-get update && apt-get install -y --no-install-recommends sqlcipher \
  && rm -rf /var/lib/apt/lists/* \
  && sqlcipher /root/enc.db "PRAGMA key = 'Password1';create table a(id int);"

RUN echo -e 'user1:kW+7AlKMnSZQIRluNxwJOMiohAw=\nuser2:oBk37hmkFgZdZ247+g6c0Ay6Vw8=\nuser3:kW+7AlKMnSZQIRluNxwJOMiohAw=' > /root/umbraco_users.pw

RUN apt-get update && apt-get install -y --no-install-recommends tightvncserver xfonts-base \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -m vncuser && mkdir ~vncuser/.vnc && echo Password | vncpasswd -f > ~vncuser/.vnc/passwd \
  && chmod 400 ~vncuser/.vnc/passwd && chown -R vncuser:vncuser ~vncuser/.vnc

RUN apt-get update \
  && apt-get install -y --no-install-recommends samba \
  && rm -rf /var/lib/apt/lists/* \
  && { for i in {3..5}; do echo -e "Password$i\nPassword$i" | smbpasswd -a "user$i"; done; } \
  && sed -ie 's,map to guest =,#map to guest =,' /etc/samba/smb.conf

RUN apt-get update \
  && apt-get install -y --no-install-recommends snmpd snmp \
  && rm -rf /var/lib/apt/lists/* \
  && sed -ie 's,^agentaddress .*$,agentaddress udp:161,' /etc/snmp/snmpd.conf \
  && echo 'createUser user3 SHA authPass AES privPass' >> /var/lib/snmp/snmpd.conf \
  && echo 'rouser user3 priv .1' >> /etc/snmp/snmpd.conf

RUN echo -e "echo Starting services\n\
service vsftpd start\n\
service ssh start\n\
/usr/sbin/inetd\n\
service postfix start\n\
service dovecot start\n\
service apache2 start\n\
ulimit -n 1024; service slapd start\n\
service mysql start\n\
service postgresql start\n\
sh /usr/local/sbin/start-tomcat.sh\n\
socat tcp-l:106,fork,reuseaddr exec:/usr/sbin/poppassd &\n\
socat tcp-l:4444,fork,reuseaddr exec:\"echo -e 'W\xe1\xc0me'\" &\n\
su - vncuser -c 'vncserver -rfbport 5900'\n\
service smbd start\n\
service snmpd start\n\
tail -f /dev/null\n" > /usr/local/sbin/start-all-services.sh

CMD ["sh", "/usr/local/sbin/start-all-services.sh"]