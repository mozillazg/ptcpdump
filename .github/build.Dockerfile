FROM golang:1.26.2-bookworm@sha256:e1b367ff64fba58a08544465ad6574a619be7517f9a517ff982374d1fd1085fa
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
