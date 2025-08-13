FROM golang:1.24.6-bookworm@sha256:bdc7cfd953b2701fcd95fd591ea3d788f41e4b74f21f1787b9f9843a28e72196
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
