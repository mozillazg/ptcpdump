FROM golang:1.23.6-bookworm@sha256:72d8b5632e67e6233130b7f7a3a5396b9fcaa45f5b949b724d4bf1fe46d369fd
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
