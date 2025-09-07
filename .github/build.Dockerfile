FROM golang:1.24.7-bookworm@sha256:08268bff0df66aff6d4f7fcf1b625fcf4f86fb7e6dbb5fdb8bb94f0920025ceb
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
