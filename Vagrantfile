# -*- mode: ruby -*-
# vi: set ft=ruby :

$apt = <<SCRIPT
export DEBIAN_FRONTEND=noninteractive 

# refresh
apt-get update -y

# essentials
apt-get install -y tmux git wget build-essential vim

# requirements.txt deps
apt-get install -y libcurl4-openssl-dev python3-dev libssl-dev # pycurl
apt-get install -y ldap-utils # ldapsearch
apt-get install -y libmysqlclient-dev # mysqlclient-python
apt-get install -y ike-scan unzip default-jdk
apt-get install -y libsqlite3-dev libsqlcipher-dev # pysqlcipher
apt-get install -y libpq-dev # psycopg2

# xfreerdp
apt-get install -y git-core cmake xsltproc libssl-dev libx11-dev libxext-dev libxinerama-dev libxcursor-dev libxdamage-dev libxv-dev libxkbfile-dev libasound2-dev libcups2-dev libxml2 libxml2-dev libxrandr-dev libxi-dev libgstreamer-plugins-base1.0-dev
git clone https://github.com/FreeRDP/FreeRDP/ /tmp/FreeRDP && (cd /tmp/FreeRDP && cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_SSE2=ON . && make && sudo make install)

SCRIPT

$patator = <<SCRIPT
python3 -m venv patatorenv --without-pip
source patatorenv/bin/activate
wget --quiet -O - https://bootstrap.pypa.io/get-pip.py | python3
pip install patator

SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.box_check_update = false
 
  # prevent TTY error messages
  config.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"

  config.vm.provision "shell",
                      inline: $apt,
                      preserve_order: true,
                      privileged: true 

  config.vm.provision "shell",
                      inline: $patator,
                      preserve_order: true,
                      privileged: false
end
