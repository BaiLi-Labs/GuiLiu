BINARY := bin/guiliu
VERSION := $(shell cat internal/version/VERSION)
COMMIT ?= $(shell git describe --always --dirty --exclude='*' 2>/dev/null || echo dev)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/BaiLi-Labs/GuiLiu/internal/version.Commit=$(COMMIT) \
	-X github.com/BaiLi-Labs/GuiLiu/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: build web web-dev run dev mock admin test vet fmt tidy clean docker version version-check version-set

version:
	@cat internal/version/VERSION

version-check:
	node scripts/version.mjs check "$(VERSION)"

version-set:
	node scripts/version.mjs set "$(NEXT_VERSION)"

# The React build is embedded by Go. Run it before the Go binary so a clean
# checkout always ships the exact assets that are in this commit.
web: version-check
	cd web && npm ci --no-audit --no-fund && npm run build

web-dev:
	cd web && npm run dev

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/guiliu

# Production-like: login is required.
run: build
	./$(BINARY) serve

# Local development: authentication disabled. Never expose this listener.
dev: build
	GUILIU_DEV=1 ./$(BINARY) serve

# Synthetic alerts from six clouds, in-memory DB, no login.
mock: build
	@echo "Mock console: http://127.0.0.1:8081 (no login, 6 cloud providers)"
	GUILIU_CONFIG=configs/mock.json ./$(BINARY) serve

# First admin bootstrap. Reads the password from the environment, not argv.
admin: build
	@if [ -z "$$GUILIU_NEW_PASSWORD" ]; then echo 'export GUILIU_NEW_PASSWORD="..." first'; exit 1; fi
	./$(BINARY) user add -username admin -role admin

test: version-check
	go test ./...

vet: version-check
	go vet ./...

fmt:
	gofmt -w ./cmd ./internal ./web

tidy:
	go mod tidy

clean:
	rm -rf bin

docker: version-check
	docker build --build-arg COMMIT="$(COMMIT)" --build-arg BUILD_DATE="$(BUILD_DATE)" -t guiliu:$(VERSION) .
