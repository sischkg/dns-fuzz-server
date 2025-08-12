FROM alpine:latest AS builder
ARG VERSION="4.12.0"

RUN apk --update --no-cache add \
  gcc \
  make \
  musl-dev \
  libevent-dev \
  openssl-dev \
  protobuf-c-dev \
  fstrm-dev \
  wget
RUN wget https://nlnetlabs.nl/downloads/nsd/nsd-${VERSION}.tar.gz
RUN tar xzf nsd-${VERSION}.tar.gz
RUN cd nsd-${VERSION} && \
  ./configure \
     --with-static \
     --with-libevent \
     --with-pid-file=/var/run/nsd/nsd.pid \
     --with-conf-file=/etc/nsd/nsd.conf \
     --enable-pie \
     --enable-relro-now \
     --enable-root-server \
     --enable-ratelimit \
     --enable-ratelimit-default-is-off \
     --enable-tcp-fastopen \
     --enable-dnstap \
     --with-dnstap-socket-path=/var/run/nsd/dnstap.sock \
     --sysconfdir=/etc && \
   make install

FROM alpine:latest

RUN apk --update --no-cache add \
  musl \
  libevent \
  openssl \
  protobuf-c \
  fstrm \
  bash \
  tcpdump \
  strace
RUN mkdir -p \
  /etc/nsd \
  /usr/local/sbin \
  /var/db/nsd \
  /var/run/nsd && \
  addgroup nsd && \
  adduser nsd -S -G nsd && \
  chown nsd:nsd /var/run/nsd /var/db/nsd
COPY --from=builder /usr/local/sbin/nsd         /usr/local/sbin/nsd
COPY --from=builder /usr/local/sbin/nsd-control /usr/local/sbin/nsd-control

EXPOSE 53/udp 53/tcp 80/tcp 853/tcp 443/tcp

ENTRYPOINT ["/usr/local/sbin/nsd", "-d", "-c", "/etc/nsd/nsd.conf"]


