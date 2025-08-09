# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250809.053601@sha256:bbd6b17bc977bda1c239e88c2ae8886424680a4aa50a7bace0b032c9b527abd6 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:f85340bf132ae937d2c2a763b8335c9bab35d6e8293f70f606b9c6178d84f42b
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
