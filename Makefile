BINARY := bin/guiliu
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/BaiLi-Labs/GuiLiu/internal/version.Version=$(VERSION) \
	-X github.com/BaiLi-Labs/GuiLiu/internal/version.Commit=$(COMMIT) \
	-X github.com/BaiLi-Labs/GuiLiu/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: build run dev mock admin test vet fmt tidy clean docker

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/guiliu

# Production-like: login is required.
run: build
	./$(BINARY) serve

# Local development: authentication disabled. Never expose this listener.
dev: build
	GUILIU_DEV=1 ./$(BINARY) serve

# Synthetic alerts from five clouds, in-memory DB, no login.
mock: build
	@echo "Mock console: http://127.0.0.1:8081 (no login, 5 cloud providers)"
	GUILIU_CONFIG=configs/mock.json ./$(BINARY) serve

# First admin bootstrap. Reads the password from the environment, not argv.
admin: build
	@if [ -z "$$GUILIU_NEW_PASSWORD" ]; then echo 'export GUILIU_NEW_PASSWORD="..." first'; exit 1; fi
	./$(BINARY) user add -username admin -role admin

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal

tidy:
	go mod tidy

clean:
	rm -rf bin

docker:
	docker build -t guiliu:dev .
