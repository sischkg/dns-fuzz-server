
# Builder
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get -y dist-upgrade && apt-get install -y curl && apt-get clean
COPY ./pdns.list /etc/apt/sources.list.d/pdns.list
COPY ./rec-52    /etc/apt/preferences.d/rec-52

RUN curl https://repo.powerdns.com/FD380FBB-pub.asc > /etc/apt/keyrings/rec-52-pub.asc 
RUN apt-get update && \
  apt-get install -y pdns-recursor tcpdump strace bind9-dnsutils bash

COPY ./etc/powerdns/recursor.conf /etc/powerdns/
COPY ./etc/powerdns/root.hint     /etc/powerdns/

# Default DNS ports
EXPOSE 53/udp
EXPOSE 53/tcp

# Default webserver port
EXPOSE 8082/tcp

ENTRYPOINT ["/usr/sbin/pdns_recursor", "-c", "/etc/powerdns/recursor.conf", "--daemon-no", "--write-pid=no"]


