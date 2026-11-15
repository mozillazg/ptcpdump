FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
