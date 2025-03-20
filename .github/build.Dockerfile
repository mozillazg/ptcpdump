FROM golang:1.23.7-bookworm@sha256:a96b5dcb1b7d6e7565d871608ea013e9f35331c2d1c2a9aa1efa02aeef3715bf
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
