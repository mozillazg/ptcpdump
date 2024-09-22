


.PHONY: build
build:
	go build -o gohttpapp main.go
	go build -buildmode=pie -o gohttpapp_pie main.go
	go build -ldflags="-s -w" -trimpath -o gohttpapp_stripped main.go
	go build -buildmode=pie -ldflags="-s -w" -trimpath -o gohttpapp_stripped_pie main.go
