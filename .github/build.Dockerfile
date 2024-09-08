FROM golang:1.23-bookworm
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
