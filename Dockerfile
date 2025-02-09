# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250209.034952@sha256:421f6aaa6f53d77ab0439c93c2ff0a7e1989b7785edd68ac0beba9dd059a3689 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:db142d433cdde11f10ae479dbf92f3b13d693fd1c91053da9979728cceb1dc68
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
