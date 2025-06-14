# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250614.033457@sha256:11fa2370e8c33e435086e35aaa6cdb44b1a94cd4943542f055b2ab542c6d0586 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:f85340bf132ae937d2c2a763b8335c9bab35d6e8293f70f606b9c6178d84f42b
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
