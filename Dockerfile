# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250206.122734@sha256:4d26314fa22696d522eef6676310e1d6249052eccfe85e8833f4e903ee141d3b AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:5b0f33c83a97f5f7d12698df6732098b0cdb860d377f6307b68efe2c6821296f
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
