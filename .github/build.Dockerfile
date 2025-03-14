FROM golang:1.23.7-bookworm@sha256:558c9ecc3418f90a89919a9ce440a42eb130314c92401a9de19f5566a6eb275e
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
