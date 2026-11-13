# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20261108.132522@sha256:adc707796dfe1bf9ca4b6ae4a1ef53750b63017e5860518dfa34658c1e78ec33 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
