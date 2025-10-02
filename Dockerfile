# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20251002.140939@sha256:36e739a5aba616b0aa89705860b996a2cd9e87c98e76709c6b138fdf682bb1a2 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:d82f458899c9696cb26a7c02d5568f81c8c8223f8661bb2a7988b269c8b9051e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
