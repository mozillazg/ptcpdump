# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20251115.084712@sha256:be36595dfaf05fd3c329cdb6982626d0b3346e85b94c7694dc5727568e53d0e9 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:d82f458899c9696cb26a7c02d5568f81c8c8223f8661bb2a7988b269c8b9051e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
