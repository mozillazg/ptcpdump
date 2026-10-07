# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20261003.144200@sha256:82e9cb1a0bc41b4f61bdf6f0b27f901602b911b5367db477eac19adad7cbe892 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
