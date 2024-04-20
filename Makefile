
.PHONY: build
build: generate
	go build

.PHONY: generate
generate:
	go generate ./...

.PHONY: run
run:
	sudo ./ptcpdump
