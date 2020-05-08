FROM ubuntu:bionic

ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt update && apt dist-upgrade -y && \
    apt install -y python3 python3-pip python3-venv git libc6:i386 libncurses5:i386 libstdc++6:i386 multiarch-support adb bsdutils git wget curl bison flex pkg-config && \
    mkdir -p /opt && cd /opt && mkdir cmake && cd cmake && wget -O cmake.sh https://github.com/`wget -q -O- https://github.com/Kitware/CMake/releases/latest | grep download | grep Linux | grep \.sh | cut -d '"' -f 2` && chmod +x cmake.sh && ./cmake.sh --skip-license && export PATH=$PWD/bin:$PATH && \
    mkdir -p /opt && cd /opt && git clone https://github.com/radareorg/radare2.git && cd radare2 && ./sys/install.sh && r2pm init && r2pm install r2ghidra-dec && \
    cd /opt && git clone --depth=1 https://github.com/angr/angr-dev.git && cd angr-dev && echo I know this is a bad idea. | ./setup.sh -i

COPY . /opt/revenge/

RUN cd /opt/revenge && pip3 install -e .[dev]

WORKDIR /opt/revenge
