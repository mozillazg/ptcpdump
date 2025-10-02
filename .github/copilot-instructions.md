# Copilot Instructions for ptcpdump

## Project Overview

ptcpdump is a tcpdump-compatible packet analyzer powered by eBPF that automatically annotates packets with process/container/pod metadata. It's written in Go and uses eBPF (Extended Berkeley Packet Filter) for kernel-space packet capture.

## Development Environment

### Required Tools
- Go >= 1.23
- Clang/LLVM >= 14
- Bison >= 3.8
- Lex/Flex >= 2.6
- GCC
- GNU make
- autoconf
- libelf

### Building the Project

```bash
# Build with static linking (default)
make build

# Build with dynamic linking
make build-dynamic-link

# Build eBPF bytecode
make build-bpf

# Build via Docker
make build-via-docker
```

### Testing

```bash
# Run unit tests
make test

# Run e2e tests (requires sudo)
make e2e

# Run linting and formatting
make lint
```

## Code Structure

- `bpf/` - eBPF C code for kernel-space packet capture
- `cmd/` - CLI commands and main application logic
- `internal/` - Internal Go packages
  - `capturer/` - Packet capture logic
  - `consumer/` - Packet processing
  - `event/` - Event handling
  - `metadata/` - Process/container/pod metadata management
  - `parser/` - Packet parsing
  - `types/` - Common types and data structures
  - `writer/` - Output writers (pcap, pcapng)
- `testdata/` - E2E test scripts

## Coding Standards

### Go Code
- Follow standard Go formatting (`go fmt`)
- Run `go vet` before committing
- Write unit tests for new functionality
- Use meaningful variable and function names
- Add godoc comments for exported functions and types

### C/eBPF Code
- Follow the clang-format configuration in `.clang-format`
- Format with: `clang-format -i bpf/ptcpdump.c bpf/*.h`
- Keep eBPF code simple and efficient
- Minimize memory allocations in hot paths
- Use eBPF helpers and kernel structures properly

### Test Files
- Unit tests: `*_test.go` files alongside source code
- E2E tests: Bash scripts in `testdata/`
- Run existing tests before and after changes
- Add tests for new features

## Key Considerations

### eBPF Development
- eBPF code runs in kernel space with strict limitations
- Generated Go code from eBPF is committed (bpf_*.go files)
- Regenerate eBPF bytecode with `make build-bpf` after modifying C code
- Test on both x86_64 and arm64 architectures when possible

### Container/Kubernetes Support
- The project integrates with Docker, containerd, and Kubernetes
- Metadata extraction requires proper permissions and runtime access
- Test with both Docker and containerd when modifying container code

### Performance
- Packet capture can be high throughput
- Minimize allocations in hot paths
- Use efficient data structures
- Consider BPF filtering to reduce userspace load

### Dependencies
- Use `go mod tidy` to manage Go dependencies
- Vendor dependencies with `go mod vendor`
- libpcap is built from submodule in `lib/libpcap`

## Common Tasks

### Adding a New Feature
1. Write unit tests first if applicable
2. Implement the feature in appropriate packages
3. Update eBPF code if kernel-space changes needed
4. Run `make lint build test` to validate
5. Add E2E test script in `testdata/` if needed
6. Update documentation in README.md if user-facing

### Fixing a Bug
1. Reproduce the issue
2. Add a test that fails with the bug
3. Fix the bug
4. Verify the test passes
5. Run full test suite to ensure no regression

### Modifying eBPF Code
1. Edit `bpf/ptcpdump.c` or related headers
2. Run `make build-bpf` to regenerate bytecode
3. Test thoroughly as kernel code errors can crash systems
4. Format with clang-format

## Build Artifacts

The following are generated and should not be manually edited:
- `bpf/*_bpfel.go` - Generated from eBPF C code
- `bpf/*_bpfel.o` - Compiled eBPF bytecode
- `output/` - Build artifacts directory
- `vendor/` - Vendored dependencies

## CI/CD

- GitHub Actions runs tests on every PR
- x86_64 tests run on GitHub Actions
- arm64 tests run on CircleCI
- All tests must pass before merging
- Docker images are built for releases

## Documentation

- README.md: Main documentation (English)
- README.zh-CN.md: Chinese documentation
- docs/: Hugo-based documentation site
- Keep documentation in sync with code changes
- Update CHANGELOG.md for notable changes

## Contributing

- Follow the existing code style
- Write clear commit messages
- Keep changes focused and minimal
- Test thoroughly before submitting
- Be respectful and follow CODE_OF_CONDUCT.md
