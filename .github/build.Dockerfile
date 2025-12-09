FROM golang:1.25.5-bookworm@sha256:cbd59ce363d162d31192b1bcf928773b6f8490ffd529c51594fc4d4ba755b8a5
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
