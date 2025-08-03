# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250614.033457@sha256:11fa2370e8c33e435086e35aaa6cdb44b1a94cd4943542f055b2ab542c6d0586 AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:f9a104fddb33220ec80fc45a4e606c74aadf1ef7a3832eb0b05be9e90cd61f5f
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
