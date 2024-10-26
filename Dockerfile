# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:latest as build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
