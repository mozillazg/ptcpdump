# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250209.034952@sha256:421f6aaa6f53d77ab0439c93c2ff0a7e1989b7785edd68ac0beba9dd059a3689 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:a5d0ce49aa801d475da48f8cb163c354ab95cab073cd3c138bd458fc8257fbf1
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
