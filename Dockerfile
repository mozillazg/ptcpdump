# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20261115.145342@sha256:c5d093a9f4b96930f9957cf0f935ebf8f2948333be25ea3f59bfb414786eb1df AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:a46257e06c82ad85242d0d38077d0a52d9896389ca60a1a59d3463db586e5fa4
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
