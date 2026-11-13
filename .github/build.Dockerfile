FROM golang:1.27.3-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
