# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250411.125935@sha256:1fa41dc9eeaf11db845b99e9255e91dfa44150d8b3d69105209cd64fce282ab4 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:37f7b378a29ceb4c551b1b5582e27747b855bbfaa73fa11914fe0df028dc581f
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
