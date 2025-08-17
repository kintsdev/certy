.PHONY: build test clean run-example install

# Build the library
build:
	go build -o bin/certy .

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Run the example
run-example:
	cd example && go run main.go

# Build the example
build-example:
	cd example && go build -o ../bin/example main.go

# Install the library
install:
	go install .

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run

# Check for security vulnerabilities
security:
	gosec ./...

# Generate documentation
docs:
	godoc -http=:6060

# Update dependencies
deps:
	go mod tidy
	go mod download

# Show dependency tree
deps-tree:
	go mod graph

# Benchmark tests
bench:
	go test -bench=. ./...

# Race condition detection
race:
	go test -race ./...

# All-in-one command
all: clean fmt lint test build

# Help
help:
	@echo "Available commands:"
	@echo "  build          - Build the library"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  clean          - Clean build artifacts"
	@echo "  run-example    - Run the example application"
	@echo "  build-example  - Build the example application"
	@echo "  install        - Install the library"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo "  security       - Check for security vulnerabilities"
	@echo "  docs           - Generate documentation"
	@echo "  deps           - Update dependencies"
	@echo "  deps-tree      - Show dependency tree"
	@echo "  bench          - Run benchmarks"
	@echo "  race           - Run tests with race detection"
	@echo "  all            - Run all checks and build"
	@echo "  help           - Show this help message"
