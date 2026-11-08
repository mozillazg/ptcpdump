# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20261101.131133@sha256:d361f4aea50cf15629a31bdca9b5625d4ce0554cbc4b1874d1979409520942b6 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
