# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20251002.133056@sha256:0c207966630a50537c57d88960cd85143431544e52f7e417cecb3e98fd4b81c6 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:d82f458899c9696cb26a7c02d5568f81c8c8223f8661bb2a7988b269c8b9051e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
