.PHONY: all build test test-race fmt vet clean install static release

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

BINARY := key-daemon

all: test build

build:
	go build -o $(BINARY) ./cmd/key-daemon

static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 ./cmd/key-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 ./cmd/key-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build $(LDFLAGS) -o $(BINARY)-linux-386 ./cmd/key-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build $(LDFLAGS) -o $(BINARY)-linux-arm ./cmd/key-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=ppc64le go build $(LDFLAGS) -o $(BINARY)-linux-ppc64le ./cmd/key-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=s390x go build $(LDFLAGS) -o $(BINARY)-linux-s390x ./cmd/key-daemon
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 go build $(LDFLAGS) -o $(BINARY)-linux-riscv64 ./cmd/key-daemon

test:
	go test ./...

test-race:
	go test -race ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY)-linux-*

install: build
	install -Dm755 $(BINARY) /usr/local/bin/$(BINARY)
	install -Dm644 key-daemon.service /etc/systemd/system/key-daemon.service
	mkdir -p /etc/key-daemon
	[ -f /etc/key-daemon/config.yaml ] || install -Dm644 config.yaml.example /etc/key-daemon/config.yaml
	 systemctl daemon-reload

release: static
	@echo "Release artifacts built:"
	@ls -la $(BINARY)-linux-*
