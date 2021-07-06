FROM ubuntu:18.04

MAINTAINER Sebastien Macke <lanjelot@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update \
  && apt-get install -y \
    build-essential python3-setuptools \
    libcurl4-openssl-dev python3-dev libssl-dev \
    ldap-utils \
    libmariadbclient-dev \
    libpq-dev \
    ike-scan unzip default-jdk \
    libsqlite3-dev libsqlcipher-dev \
    python3-pip python-pip \
  && rm -rf /var/lib/apt/lists/*

# cx_oracle
RUN apt-get update \
  && apt-get install -y libaio1 wget unzip git \
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

RUN git clone --branch 5.3 https://github.com/oracle/python-cx_Oracle \
 && cd python-cx_Oracle && export ORACLE_HOME=$(echo /opt/oracle/instantclient_*) && python2 setup.py build && python2 setup.py install

# xfreerdp (see https://github.com/FreeRDP/FreeRDP/wiki/Compilation)
RUN apt-get update && apt-get install -y ninja-build build-essential git-core debhelper cdbs dpkg-dev autotools-dev cmake pkg-config xmlto libssl-dev docbook-xsl xsltproc libxkbfile-dev libx11-dev libwayland-dev libxrandr-dev libxi-dev libxrender-dev libxext-dev libxinerama-dev libxfixes-dev libxcursor-dev libxv-dev libxdamage-dev libxtst-dev libcups2-dev libpcsclite-dev libasound2-dev libpulse-dev libjpeg-dev libgsm1-dev libusb-1.0-0-dev libudev-dev libdbus-glib-1-dev uuid-dev libxml2-dev libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libfaad-dev libfaac-dev \
 && apt-get install -y libavutil-dev libavcodec-dev libavresample-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/FreeRDP
RUN git clone https://github.com/FreeRDP/FreeRDP/ .
RUN cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_SSE2=ON . && cmake --build . && cmake --build . --target install

WORKDIR /opt/patator
COPY ./requirements.txt ./
RUN python3 -m pip install --upgrade pip \
  && python3 -m pip install -r requirements.txt

RUN sed -e '/cx_Oracle/d' -e 's,pysqlcipher3,pysqlcipher,' requirements.txt | python2 -m pip install -r /dev/stdin

# utils
RUN apt-get update && apt-get install -y ipython3 ipython iputils-ping iproute2 netcat curl rsh-client telnet vim mlocate nmap \
  && rm -rf /var/lib/apt/lists/*
RUN echo 'set bg=dark' > /root/.vimrc

COPY ./patator.py ./
ENTRYPOINT ["python3", "./patator.py"]
