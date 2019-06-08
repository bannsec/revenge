FROM ubuntu:bionic

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && apt dist-upgrade -y && \
    apt install -y python3 python3-pip python3-venv && \
    mkdir -p /opt

COPY . /opt/frida-util/

RUN cd /opt/frida-util && pip3 install -e .[dev]

WORKDIR /opt/frida-util
