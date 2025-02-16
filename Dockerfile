FROM python:3.13

# dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
  build-essential python3-setuptools \
  libcurl4-openssl-dev python3-dev libssl-dev \
  ldap-utils \
  libmariadb-dev \
  libpq-dev \
  ike-scan unzip default-jdk \
  libsqlite3-dev \
  libsqlcipher-dev \
  python3-pip \
  pkg-config \
 && rm -rf /var/lib/apt/lists/*

## cx_oracle
RUN apt-get update \
 && apt-get install -y --no-install-recommends libaio1 wget unzip git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/oracle
RUN wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-basiclite-linuxx64.zip \
 && wget https://download.oracle.com/otn_software/linux/instantclient/instantclient-sdk-linuxx64.zip \
 && unzip instantclient-basiclite-linuxx64.zip \
 && unzip -n instantclient-sdk-linuxx64.zip \
 && rm -f instantclient-basiclite-linuxx64.zip \
 && rm -f instantclient-sdk-linuxx64.zip \
 && cd /opt/oracle/instantclient_* \
 && rm -f *jdbc* *occi* *mysql* *README *jar uidrvci genezi adrci \
 && echo /opt/oracle/instantclient_* > /etc/ld.so.conf.d/oracle-instantclient.conf \
 && ldconfig

## xfreerdp (see https://github.com/FreeRDP/FreeRDP/wiki/Compilation)
WORKDIR /opt/FreeRDP
RUN apt-get update \
  && apt-get install -y --no-install-recommends ninja-build build-essential git-core debhelper cdbs dpkg-dev cmake cmake-curses-gui clang-format ccache opencl-c-headers ocl-icd-opencl-dev libmp3lame-dev libopus-dev libsoxr-dev libpam0g-dev pkg-config xmlto libssl-dev docbook-xsl xsltproc libxkbfile-dev libx11-dev libwayland-dev libxrandr-dev libxi-dev libxrender-dev libxext-dev libxinerama-dev libxfixes-dev libxcursor-dev libxv-dev libxdamage-dev libxtst-dev libcups2-dev libpcsclite-dev libasound2-dev libpulse-dev libgsm1-dev libusb-1.0-0-dev uuid-dev libxml2-dev libfaad-dev libsdl2-dev libsdl2-ttf-dev libcjson-dev libpkcs11-helper-dev liburiparser-dev libkrb5-dev libsystemd-dev libfuse3-dev libswscale-dev libcairo2-dev libavutil-dev libavcodec-dev libswresample-dev libwebkit2gtk-4.0-dev libpkcs11-helper1-dev \
  && rm -rf /var/lib/apt/lists/* \
  && git clone --depth 1 --branch 3.12.0 https://github.com/freerdp/freerdp.git \
  && cmake -GNinja -B freerdp-build -S freerdp -DCMAKE_BUILD_TYPE=Debug -DCMAKE_SKIP_INSTALL_ALL_DEPENDENCY=ON -DWITH_SERVER=OFF -DWITH_SAMPLE=OFF -DWITH_PLATFORM_SERVER=OFF -DUSE_UNWIND=OFF -DWITH_SWSCALE=OFF -DWITH_FFMPEG=OFF -DWITH_WEBVIEW=OFF \
  && cmake --build freerdp-build \
  && cmake --install freerdp-build \
  && rm -rf /opt/FreeRDP

# patator
WORKDIR /opt/patator
COPY ./requirements.txt ./
RUN python3 -m pip install --upgrade pip \
  && python3 -m pip install -r requirements.txt

# utils
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping iproute2 netcat-openbsd curl rsh-client telnet vim mlocate nmap \
 && rm -rf /var/lib/apt/lists/* \
 && pip install -U IPython \
 && echo 'set bg=dark' > /root/.vimrc

COPY ./patator.py ./
ENTRYPOINT ["python3", "./patator.py"]
