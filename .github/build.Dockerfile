FROM golang:1.25.0-bookworm@sha256:d987118a23e6b899fe42b53408b56bc2ddc11bbe6770edef9189299f44512240
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
