FROM golang:1.26.3-bookworm@sha256:3ec7c08c92531773db5f83572fc0d1ceac66465050f12fd11383c397189ae19d
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
