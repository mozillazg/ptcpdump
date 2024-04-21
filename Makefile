
.PHONY: build
build: generate
	CGO_ENABLED=0 go build -ldflags '-extldflags "-static"'

.PHONY: generate
generate:
	go generate ./...

.PHONY: run
run:
	sudo ./ptcpdump
