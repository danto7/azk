.PHONY: build test test-integration lint fmt vet e2e floci-up floci-down tidy

BIN := bin/azk

build:
	go build -o $(BIN) ./cmd/azk

test:
	go test -race ./...

# Needs Docker; starts floci-az via testcontainers.
test-integration:
	go test -race -tags integration -count=1 ./test/integration/...

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .

vet:
	go vet -tags integration ./...

tidy:
	go mod tidy

e2e: build
	cd test/e2e && npm ci && npx playwright test

floci-up:
	docker compose up -d floci-az

floci-down:
	docker compose down
