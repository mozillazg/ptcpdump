FROM golang:1.26.3-bookworm@sha256:b09e568dcf2a1ff3ce09a230ea234193fc014dc195472fe63316e50238453d96
RUN apt update && apt install -y clang gcc flex bison make autoconf \
        gcc-arm-linux-gnueabi libc6-dev-armhf-cross \
        libelf-dev gcc-aarch64-linux-gnu libc6-dev-arm64-cross git && \
    git config --global --add safe.directory /app
WORKDIR /app
