all: build

build:
	@echo "Building xrps and xrpc..."
	@go build -o bin/xrps ./xrps
	@go build -o bin/xrpc ./xrpc

build-ui:
	@echo "Building front-end UIs (xrps/web, xrpc/web)..."
	@cd xrps/web && npm run build --silent || (echo "xrps/web build failed" && exit 1)
	@cd xrpc/web && npm run build --silent || (echo "xrpc/web build failed" && exit 1)

build-embed: build-ui
	@echo "Building xrps and xrpc with embedded UI..."
	@go build -tags ui_embed -o bin/xrps ./xrps
	@go build -tags ui_embed -o bin/xrpc ./xrpc

run-xrps:
	@go run ./xrps -addr :8080

run-xrpc:
	@go run ./xrpc -addr :8081

clean:
	rm -rf bin
