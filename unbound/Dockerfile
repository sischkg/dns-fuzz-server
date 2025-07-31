FROM alpine:latest AS builder
ARG VERSION="1.23.1"

RUN apk --update --no-cache add \
  gcc \
  make \
  musl-dev \
  libevent-dev \
  openssl-dev \
  protobuf-c-dev \
  fstrm-dev \
  wget \
  nghttp2-dev \
  expat-dev \
  byacc \
  flex
RUN wget https://nlnetlabs.nl/downloads/unbound/unbound-${VERSION}.tar.gz
RUN tar xzf unbound-${VERSION}.tar.gz
RUN cd unbound-${VERSION} && \
  ./configure \
     --with-static \
     --with-libevent \
     --with-pid-file=/var/run/unbound/unbound.pid \
     --with-conf-file=/etc/unbound/unbound.conf \
     --enable-pie \
     --enable-relro-now \
     --enable-dnstap \
     --with-libnghttp2 \
     --with-dnstap-socket-path=/var/run/unbound/dnstap.sock \
     --sysconfdir=/etc && \
   make install

FROM alpine:latest

RUN apk --update --no-cache add \
  musl \
  libevent \
  openssl \
  protobuf-c \
  fstrm \
  nghttp2 \
  expat \
  bash \
  tcpdump \
  strace
RUN mkdir -p \
  /etc/unbound \
  /usr/local/sbin \
  /var/run/unbound && \
  addgroup unbound && \
  adduser unbound -S -G unbound unbound && \
  chown unbound:unbound /var/run/unbound
COPY --from=builder /usr/local/sbin/unbound         /usr/local/sbin/unbound
COPY --from=builder /usr/local/sbin/unbound-control /usr/local/sbin/unbound-control
COPY ./etc/unbound/unbound.conf /etc/unbound/unbound.conf
COPY ./etc/unbound/unbound_control.pem /etc/unbound/unbound_control.pem
COPY ./etc/unbound/unbound_control.key /etc/unbound/unbound_control.key
COPY ./etc/unbound/unbound_server.pem  /etc/unbound/unbound_server.pem
COPY ./etc/unbound/unbound_server.key  /etc/unbound/unbound_server.key

ENTRYPOINT ["/usr/local/sbin/unbound", "-d", "-c", "/etc/unbound/unbound.conf"]


