FROM golang:1.23-bookworm@sha256:37a5567517b25789e0405404d97b68a61e63d3ad1e58dcdd4a4d141e89f9fdeb
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
