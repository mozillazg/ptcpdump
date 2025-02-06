# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:latest@sha256:b2d795029bcdef857a58158b7cd437ab0c65206a30e7b6fc9a6bcb1d2ca8b84a as build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:5b0f33c83a97f5f7d12698df6732098b0cdb860d377f6307b68efe2c6821296f
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
