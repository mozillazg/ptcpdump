.ONESHELL:
SHELL = /bin/sh

GIT = $(shell which git || /bin/false)
OUTPUT = ./output

BPF_SRC = ./bpf
LIBPCAP = ./lib/libpcap
LIBPCAP_SRC =  $(abspath $(LIBPCAP))
LIBPCAP_DIST_DIR ?= $(abspath $(OUTPUT)/libpcap)
LIBPCAP_HEADER_DIR = $(abspath $(LIBPCAP_DIST_DIR)/include)
LIBPCAP_OBJ_DIR = $(abspath $(LIBPCAP_DIST_DIR)/lib)
LIBPCAP_OBJ = $(abspath $(LIBPCAP_OBJ_DIR)/libpcap.a)

GIT_COMMIT ?= $(shell git rev-parse --short HEAD)
VERSION ?= $(shell git describe --tags --abbrev=0)
CGO_CFLAGS_STATIC = "-I$(LIBPCAP_HEADER_DIR)"
CGO_LDFLAGS_STATIC = "-L$(LIBPCAP_OBJ_DIR) -lpcap $(LIBPCAP_OBJ)"
CGO_ENABLED ?= 1
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
LDFLAGS := -linkmode "external" -extldflags "-static"
LDFLAGS += -X github.com/mozillazg/ptcpdump/internal.Version=$(VERSION)
LDFLAGS += -X github.com/mozillazg/ptcpdump/internal.GitCommit=$(GIT_COMMIT)

CARCH ?= $(shell uname -m)
LIBPCAP_ARCH = $(CARCH)-unknown-linux-gnu
LIBPCAP_CC ?= gcc

.PHONY: libpcap
libpcap: $(LIBPCAP_OBJ)

$(LIBPCAP_OBJ): $(LIBPCAP_SRC)/configure $(wildcard $(LIBPCAP_SRC)/*.[ch]) | $(LIBPCAP_DIST_DIR)
	cd $(LIBPCAP_SRC) && \
	  CC=$(LIBPCAP_CC) ./configure --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl \
	  	--host=$(LIBPCAP_ARCH) && \
	  $(MAKE) && \
	  $(MAKE) install prefix=$(LIBPCAP_DIST_DIR)

$(LIBPCAP_SRC)/configure:
ifeq ($(wildcard $@), )
	echo "INFO: updating submodule 'libpcap'"
	$(GIT) submodule update --init --recursive
endif

$(LIBPCAP_DIST_DIR): $(LIBPCAP_SRC)

$(OUTPUT):
	mkdir -p $(OUTPUT)


.PHONY: build
build: libpcap
	CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	CGO_ENABLED=1 go build -tags static -ldflags "$(LDFLAGS)"

.PHONY: test
test:
	CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	CGO_ENABLED=1 go test -v ./...

.PHONY: generate
generate: build-bpf

.PHONY: build-bpf
build-bpf:
	TARGET=amd64 go generate ./...
	TARGET=arm64 go generate ./...

.PHONY: lint
lint: deps fmt

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: deps
deps:
	go mod tidy

.PHONY: e2e
e2e: lint build-bpf build
	sudo rm -rf /tmp/ptcpdump_*
	sudo bash testdata/test_default.sh ./ptcpdump
	sudo bash testdata/test_base.sh ./ptcpdump
	sudo bash testdata/test_pname_filter.sh ./ptcpdump
	sudo bash testdata/test_pid_filter.sh ./ptcpdump
	sudo bash testdata/test_read_pcap.sh ./ptcpdump
	sudo bash testdata/test_write_pcap.sh ./ptcpdump
	sudo bash testdata/test_exist_connection.sh ./ptcpdump
	sudo bash testdata/test_arp.sh ./ptcpdump
	sudo bash testdata/test_icmp.sh ./ptcpdump
	sudo bash testdata/test_sub_program.sh ./ptcpdump
	sudo bash testdata/test_sub_curl_domain_program.sh ./ptcpdump
	sudo bash testdata/test_write_stdout.sh ./ptcpdump

.PHONY: clean
clean:
	$(MAKE) -C $(LIBPCAP_SRC) clean
	rm -rf $(OUTPUT)
	rm -f ./ptcpdump
