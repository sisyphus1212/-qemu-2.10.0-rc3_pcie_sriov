# docker run -itd --name qemu_2.7 --hostname docker --privileged -v /home/lcj/qemu-hdl-cosim/qemu/qemu-2.10.0-rc3:/root/qemu  -w /root f9a80a55f492
#  (sudo -E  qemu-system-x86_64 -hda ./test.raw  -enable-kvm -m 1G   -smp cores=1 -device accelerator-pcie -redir tcp:2200::22  -serial mon:stdio -display none)
# 使用 Ubuntu 18.04 基础镜像
FROM ubuntu:18.04

# 设置非交互式安装，避免在安装过程中出现提示
ARG DEBIAN_FRONTEND=noninteractive

# 设置环境变量
ENV http_proxy=http://192.168.133.1:10809 \
    https_proxy=http://192.168.133.1:10809
# 更新软件包列表并安装编译 QEMU 所需的包
RUN apt-get update
RUN apt-get install -y gcc
RUN apt-get install -y g++
RUN apt-get install -y make
RUN apt-get install -y libglib2.0-dev
RUN apt-get install -y libfdt-dev
RUN apt-get install -y libpixman-1-dev
RUN apt-get install -y zlib1g-dev
RUN apt-get install -y python sudo
RUN apt-get install -y git iproute2  net-tools
RUN apt-get install -y pkg-config
RUN apt-get install -y libzmq3-dev libczmq-dev libncurses5-dev libncursesw5-dev libsdl2-dev

# 清理缓存，减小镜像大小
RUN apt-get  clean && \
    rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /qemu