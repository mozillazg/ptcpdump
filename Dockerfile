# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:latest@sha256:cc6ea2234b7fe2a831e30074abccb24cc4cbc27695f2573a853c3ec19e4ba809 as build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:db142d433cdde11f10ae479dbf92f3b13d693fd1c91053da9979728cceb1dc68
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
