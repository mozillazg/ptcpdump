# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20251206.054007@sha256:043bfa0c026e694d440b32e1ded04b88ca13dd094179efabc1977c3a41330f15 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:d82f458899c9696cb26a7c02d5568f81c8c8223f8661bb2a7988b269c8b9051e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
