FROM golang:1.23.8-bookworm@sha256:1a73e15c5a17855b58014aab45df0fdf8be778f12a62ed2a48009fe2c0022091
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
