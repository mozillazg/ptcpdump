# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20261003.144200@sha256:82e9cb1a0bc41b4f61bdf6f0b27f901602b911b5367db477eac19adad7cbe892 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
