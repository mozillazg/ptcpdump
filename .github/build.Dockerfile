FROM golang:1.25.4-bookworm@sha256:c5a9ab37ec9e3103266a8c97c6eb8dfe3faca599737afc6ba2e8a5488adb13ae
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
