# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250411.125935@sha256:1fa41dc9eeaf11db845b99e9255e91dfa44150d8b3d69105209cd64fce282ab4 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:a5d0ce49aa801d475da48f8cb163c354ab95cab073cd3c138bd458fc8257fbf1
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
