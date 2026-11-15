# .github/build.Dockerfile
FROM quay.io/ptcpdump/develop:20261115.145342@sha256:c5d093a9f4b96930f9957cf0f935ebf8f2948333be25ea3f59bfb414786eb1df AS build
WORKDIR /app
COPY . .
RUN make build

FROM busybox:latest@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e
WORKDIR /ptcpdump
COPY --from=build /app/ptcpdump /usr/local/bin/
