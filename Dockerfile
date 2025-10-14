# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20251002.133056@sha256:0c207966630a50537c57d88960cd85143431544e52f7e417cecb3e98fd4b81c6 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:2f590fc602ce325cbff2ccfc39499014d039546dc400ef8bbf5c6ffb860632e7
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
