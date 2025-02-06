# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250206.122734@sha256:4d26314fa22696d522eef6676310e1d6249052eccfe85e8833f4e903ee141d3b AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:db142d433cdde11f10ae479dbf92f3b13d693fd1c91053da9979728cceb1dc68
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
