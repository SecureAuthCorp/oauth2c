install:
	go install .

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run

all: build test lint
