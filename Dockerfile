FROM ubuntu:latest AS builder
RUN apt update
RUN apt install -y \
  build-essential \
  libyaml-cpp-dev \
  libboost-all-dev \
  libssl-dev \
  pkg-config \
  cmake
RUN mkdir -p /build
COPY src/ /build/src
COPY tests/ /build/tests
COPY CMakeLists.txt /build/
WORKDIR /build
RUN cmake . && make

FROM ubuntu:latest AS server
RUN apt update 
RUN apt install -y \
  libyaml-cpp0.8 \
  libboost-thread1.83.0 \
  libboost-log1.83.0 \
  libboost-program-options1.83.0 \
  openssl
COPY --from=builder /build/bin/fuzz_server /usr/local/bin/fuzz_server
COPY --from=builder /build/bin/fuzz_client /usr/local/bin/fuzz_client
#COPY ./server /usr/local/etc/data

#CMD [ "/usr/local/bin/fuzz_server", "--file", "/usr/local/etc/data/example.com.zone.full", "--zone", "example.com", "--ksk", "/usr/local/etc/data/example.com.ksk.yaml", "--zsk", "/usr/local/etc/data/example.com.zsk.yaml"]


