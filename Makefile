# porthole build helpers. Works with GNU make on Linux, macOS and Git Bash/MSYS2 on Windows.

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)
BIN_DIR  ?= bin
FUZZTIME ?= 10s
# Keep in sync with .github/workflows/ci.yml.
GOVULNCHECK_VERSION ?= v1.1.4

export CGO_ENABLED = 0

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build static, stripped binaries of portholed and porthole into $(BIN_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ ./cmd/...

.PHONY: test
test: ## Run the tests
	go test -count=1 ./...

.PHONY: test-race
test-race: export CGO_ENABLED = 1
test-race: ## Run the tests with the race detector (needs a C toolchain)
	go test -race -shuffle=on -count=1 ./...

.PHONY: lint
lint: ## Run golangci-lint (v2)
	golangci-lint run

.PHONY: vuln
vuln: ## Scan dependencies and code for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

.PHONY: fuzz
fuzz: ## Short fuzzing run of the frame decoder and the token parser (FUZZTIME=10s)
	go test -run='^$$' -fuzz='^FuzzReadMessage$$' -fuzztime=$(FUZZTIME) ./internal/proto
	go test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZTIME) ./internal/auth

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	go mod tidy

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN_DIR) dist coverage.out
