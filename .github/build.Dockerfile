FROM golang:1.27.1-bookworm@sha256:6e725de5c0593b829d80b04f169d4fe119b32c612744c79e3311acf14b738e7f
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
