# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250809.053601@sha256:bbd6b17bc977bda1c239e88c2ae8886424680a4aa50a7bace0b032c9b527abd6 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:f9a104fddb33220ec80fc45a4e606c74aadf1ef7a3832eb0b05be9e90cd61f5f
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
