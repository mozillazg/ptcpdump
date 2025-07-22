FROM golang:1.24.5-bookworm@sha256:81c97ed10e57e92aa271ef8cb296cb3fb45e510634dcc1e5e76b6239150a1419
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
