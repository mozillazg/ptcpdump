.ONESHELL:
SHELL = /bin/sh

GIT = $(shell which git || /bin/false)
OUTPUT = ./output


BPF_SRC = ./bpf
LIBPCAP = ./lib/libpcap
LIBPCAP_SRC =  $(abspath $(LIBPCAP))
LIBPCAP_DIST_DIR = $(abspath $(OUTPUT)/libpcap)
LIBPCAP_HEADER_DIR = $(abspath $(LIBPCAP_DIST_DIR)/include)
LIBPCAP_OBJ_DIR = $(abspath $(LIBPCAP_DIST_DIR)/lib)
LIBPCAP_OBJ = $(abspath $(LIBPCAP_OBJ_DIR)/libpcap.a)

CGO_CFLAGS_STATIC = "-I$(LIBPCAP_HEADER_DIR)"
CGO_LDFLAGS_STATIC = "-L$(LIBPCAP_OBJ_DIR) -lelf -lz $(LIBPCAP_OBJ)"


.PHONY: libpcap
libpcap: $(LIBPCAP_OBJ)

$(LIBPCAP_OBJ): $(LIBPCAP_SRC)/configure $(wildcard $(LIBPCAP_SRC)/*.[ch]) | $(LIBPCAP_DIST_DIR)
	cd $(LIBPCAP_SRC) && \
	  ./configure --enable-dbus=no && \
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
build: generate libpcap
	CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	CGO_ENABLED=1 go build -tags=static -ldflags '-extldflags "-static"'

.PHONY: test
test:
	CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	CGO_ENABLED=1 go test -v ./...

.PHONY: generate
generate:
	go generate ./...

.PHONY: clean
clean:
	$(MAKE) -C $(LIBPCAP_SRC) clean
	rm -rf $(OUTPUT)
	rm -f ./ptcpdump
