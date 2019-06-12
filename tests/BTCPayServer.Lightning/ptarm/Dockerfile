FROM ubuntu:18.04

RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

RUN apt-get update && apt-get install -y \
    git \
    autoconf \
    pkg-config \
    build-essential \
    libtool \
    python3 \
    wget \
    jq \
    bc

RUN apt-get install -y nodejs npm
RUN npm install n -g
RUN n stable
RUN apt purge -y nodejs npm

COPY . ptarmigan

WORKDIR ptarmigan

RUN make full

RUN cd ./ptarmapi/ && npm install

RUN cp ./tests/BTCPayServer.Lightning/ptarm/docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["./docker-entrypoint.sh"]