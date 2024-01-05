FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive 

# dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
  build-essential python3-setuptools \
  libcurl4-openssl-dev python3-dev libssl-dev \
  ldap-utils \
  libmysqlclient-dev \
  libpq-dev \
  ike-scan unzip default-jdk \
  libsqlite3-dev \
  libsqlcipher-dev \
  python3-pip \
 && rm -rf /var/lib/apt/lists/*

## cx_oracle
RUN apt-get update \
 && apt-get install -y --no-install-recommends libaio1 wget unzip git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/oracle
RUN wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip \
 && wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-sdk-linuxx64.zip \
 && unzip instantclient-basiclite-linuxx64.zip \
 && rm -f instantclient-basiclite-linuxx64.zip \
 && unzip instantclient-sdk-linuxx64.zip \
 && rm -f instantclient-sdk-linuxx64.zip \
 && cd /opt/oracle/instantclient_* \
 && rm -f *jdbc* *occi* *mysql* *README *jar uidrvci genezi adrci \
 && echo /opt/oracle/instantclient_* > /etc/ld.so.conf.d/oracle-instantclient.conf \
 && ldconfig

## xfreerdp (see https://github.com/FreeRDP/FreeRDP/wiki/Compilation)
WORKDIR /opt/FreeRDP
RUN apt-get update \
 && apt-get install -y --no-install-recommends ninja-build build-essential git-core debhelper cdbs dpkg-dev autotools-dev cmake pkg-config xmlto libssl-dev docbook-xsl xsltproc libxkbfile-dev libx11-dev libwayland-dev libxrandr-dev libxi-dev libxrender-dev libxext-dev libxinerama-dev libxfixes-dev libxcursor-dev libxv-dev libxdamage-dev libxtst-dev libcups2-dev libpcsclite-dev libasound2-dev libpulse-dev libjpeg-dev libgsm1-dev libusb-1.0-0-dev libudev-dev libdbus-glib-1-dev uuid-dev libxml2-dev libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libfaad-dev libfaac-dev libsdl2-dev libcjson-dev libpkcs11-helper1-dev \
 && apt-get install -y --no-install-recommends libavutil-dev libavcodec-dev libswresample-dev \
 && rm -rf /var/lib/apt/lists/* \
 && git clone --depth 1 --branch 2.9.0 https://github.com/freerdp/freerdp.git \
 && cmake -B freerdp-build -S freerdp -DCMAKE_BUILD_TYPE=Debug -DWITH_CLIENT_SDL=OFF -DWITH_KRB5=OFF -DWITH_SWSCALE=OFF -DWITTH_SSE2=ON -DWITH_FUSE=OFF \
 && cmake --build freerdp-build \
 && cmake --install freerdp-build \
 && rm -rf /opt/FreeRDP

# patator
WORKDIR /opt/patator
COPY ./requirements.txt ./
RUN python3 -m pip install --upgrade pip \
  && python3 -m pip install -r requirements.txt

# uncomment for python2
# RUN apt-get update \
#  && apt-get install -y --no-install-recommends python-pip ipython \
#  && rm -rf /var/lib/apt/lists/* \
#  && sed -e '/cx_Oracle/d' -e 's,pysqlcipher3,pysqlcipher,' requirements.txt | python2 -m pip install -r /dev/stdin \
#  && git clone --branch 5.3 https://github.com/oracle/python-cx_Oracle \
#  && cd python-cx_Oracle && export ORACLE_HOME=$(echo /opt/oracle/instantclient_*) && python2 setup.py build && python2 setup.py install

# utils
RUN apt-get update \
 && apt-get install -y --no-install-recommends ipython3 iputils-ping iproute2 netcat curl rsh-client telnet vim mlocate nmap \
 && rm -rf /var/lib/apt/lists/* \
 && echo 'set bg=dark' > /root/.vimrc

COPY ./patator.py ./
ENTRYPOINT ["python3", "./patator.py"]
