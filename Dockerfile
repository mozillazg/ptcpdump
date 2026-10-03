# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20251206.054007@sha256:043bfa0c026e694d440b32e1ded04b88ca13dd094179efabc1977c3a41330f15 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
