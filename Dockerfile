# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250411.125935@sha256:1fa41dc9eeaf11db845b99e9255e91dfa44150d8b3d69105209cd64fce282ab4 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:f85340bf132ae937d2c2a763b8335c9bab35d6e8293f70f606b9c6178d84f42b
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
