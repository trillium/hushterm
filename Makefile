.PHONY: build test lint install clean release-snapshot setup

build:
	go build -o hushterm .

test:
	go test -race ./...

lint:
	golangci-lint run

install:
	go install .

clean:
	rm -f hushterm

release-snapshot:
	goreleaser release --snapshot --clean

setup:
	git config core.hooksPath .githooks
