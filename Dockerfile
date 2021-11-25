FROM ubuntu:20.04

ADD . /hardsheap
WORKDIR /hardsheap

RUN apt update
RUN apt install -y sudo

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive \
  apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    autogen \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    libboost-system-dev \
    libboost-filesystem-dev \
    libtool \
    git \
    wget \
    python3 \
    python3-pip \
    ltrace

RUN pip3 install scipy

RUN ./build.sh
RUN cd artifact && ./build.sh
