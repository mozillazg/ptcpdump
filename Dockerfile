# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:latest@sha256:cc6ea2234b7fe2a831e30074abccb24cc4cbc27695f2573a853c3ec19e4ba809 as build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:5b0f33c83a97f5f7d12698df6732098b0cdb860d377f6307b68efe2c6821296f
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
