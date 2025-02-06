# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20250206.122734@sha256:4d26314fa22696d522eef6676310e1d6249052eccfe85e8833f4e903ee141d3b AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:a5d0ce49aa801d475da48f8cb163c354ab95cab073cd3c138bd458fc8257fbf1
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
