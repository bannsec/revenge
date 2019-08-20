FROM ubuntu:bionic

ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt update && apt dist-upgrade -y && \
    apt install -y python3 python3-pip python3-venv git libc6:i386 libncurses5:i386 libstdc++6:i386 multiarch-support adb && \
    mkdir -p /opt

COPY . /opt/revenge/

RUN cd /opt/revenge && pip3 install -e .[dev]

WORKDIR /opt/revenge
