FROM golang:1.23.8-bookworm@sha256:1a73e15c5a17855b58014aab45df0fdf8be778f12a62ed2a48009fe2c0022091
RUN apt update && apt install -y clang gcc flex bison make autoconf libelf-dev git \
        gcc-arm-linux-gnueabi libc6-dev-armel-cross binutils-arm-linux-gnueabi \
        gcc-arm-linux-gnueabihf libc6-dev-armhf-cross binutils-arm-linux-gnueabihf \
        gcc-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu && \
    git config --global --add safe.directory /app
WORKDIR /app
