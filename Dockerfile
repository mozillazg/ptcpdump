# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250809.053601@sha256:bbd6b17bc977bda1c239e88c2ae8886424680a4aa50a7bace0b032c9b527abd6 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:d82f458899c9696cb26a7c02d5568f81c8c8223f8661bb2a7988b269c8b9051e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
