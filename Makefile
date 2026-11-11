.PHONY: build test race test-coverage fmt vet lint clean build-example run-example all help

build:
	go build ./...

test:
	go test -v ./...

race:
	go test -race ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

fmt:
	go fmt ./...

vet:
	go vet ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

build-example:
	go build -o bin/example ./example

run-example:
	go run ./example

all: fmt vet race build

help:
	@echo "build          - Build all packages"
	@echo "test           - Run tests"
	@echo "race           - Run tests with race detection"
	@echo "test-coverage  - Run tests with coverage report"
	@echo "fmt            - Format code"
	@echo "vet            - Run go vet"
	@echo "lint           - Run golangci-lint"
	@echo "clean          - Remove build artifacts"
	@echo "build-example  - Build the example application"
	@echo "run-example    - Run the example application"
	@echo "all            - fmt, vet, race tests and build"
