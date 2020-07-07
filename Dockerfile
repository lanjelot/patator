FROM ubuntu:18.04

MAINTAINER Sebastien Macke <lanjelot@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update && apt-get install -y \
  build-essential \
  libcurl4-openssl-dev python3-dev libssl-dev \
  ldap-utils \
  libmariadbclient-dev \
  ike-scan unzip default-jdk \
  libsqlite3-dev libsqlcipher-dev \
  libpq-dev \
  python3-pip

# cx_oracle
RUN apt-get update && apt-get install -y libaio1 wget unzip
WORKDIR /opt/oracle
RUN wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip
RUN unzip instantclient-basiclite-linuxx64.zip
RUN rm -f instantclient-basiclite-linuxx64.zip
RUN cd /opt/oracle/instantclient*
RUN rm -f *jdbc* *occi* *mysql* *README *jar uidrvci genezi adrci
RUN echo /opt/oracle/instantclient* > /etc/ld.so.conf.d/oracle-instantclient.conf
RUN ldconfig

# xfreerdp (see https://github.com/FreeRDP/FreeRDP/wiki/Compilation)
RUN apt-get update && apt-get install -y ninja-build build-essential git-core debhelper cdbs dpkg-dev autotools-dev cmake pkg-config xmlto libssl-dev docbook-xsl xsltproc libxkbfile-dev libx11-dev libwayland-dev libxrandr-dev libxi-dev libxrender-dev libxext-dev libxinerama-dev libxfixes-dev libxcursor-dev libxv-dev libxdamage-dev libxtst-dev libcups2-dev libpcsclite-dev libasound2-dev libpulse-dev libjpeg-dev libgsm1-dev libusb-1.0-0-dev libudev-dev libdbus-glib-1-dev uuid-dev libxml2-dev libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libfaad-dev libfaac-dev \
 && apt-get install -y libavutil-dev libavcodec-dev libavresample-dev
RUN git clone https://github.com/FreeRDP/FreeRDP/ /tmp/FreeRDP
WORKDIR /tmp/FreeRDP
RUN cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_SSE2=ON . && cmake --build . && cmake --build . --target install

WORKDIR /opt/patator
RUN python3 -m pip install patator

ENTRYPOINT ["patator.py"]
