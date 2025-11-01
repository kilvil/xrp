all: build

build:
	@echo "Building xrps and xrpc..."
	@go build -o bin/xrps ./xrps
	@go build -o bin/xrpc ./xrpc

run-xrps:
	@go run ./xrps -addr :8080

run-xrpc:
	@go run ./xrpc -addr :8081

clean:
	rm -rf bin

