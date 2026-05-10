# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20251206.054007@sha256:043bfa0c026e694d440b32e1ded04b88ca13dd094179efabc1977c3a41330f15 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:2f590fc602ce325cbff2ccfc39499014d039546dc400ef8bbf5c6ffb860632e7
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
