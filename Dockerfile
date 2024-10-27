# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:latest@sha256:cc6ea2234b7fe2a831e30074abccb24cc4cbc27695f2573a853c3ec19e4ba809 as build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:768e5c6f5cb6db0794eec98dc7a967f40631746c32232b78a3105fb946f3ab83
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
