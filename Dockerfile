# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250411.125935@sha256:1fa41dc9eeaf11db845b99e9255e91dfa44150d8b3d69105209cd64fce282ab4 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:3308bdfbc80b8e960219232df14f233a3c56979f392f56b0d9a8bc290c7dfd76
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
