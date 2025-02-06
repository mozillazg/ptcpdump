# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:latest@sha256:5036b1610827db98d25ee1f9069a31c3f219a4c511a4e56dbfd12e71487fdfdc AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:5b0f33c83a97f5f7d12698df6732098b0cdb860d377f6307b68efe2c6821296f
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
