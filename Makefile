all: build

build:
	@echo "Building xrp (merged backend from src)..."
	@go build -o bin/xrp ./src

build-ui:
	@echo "Building merged front-end (web)..."
	@cd web && npm run build --silent || (echo "web build failed" && exit 1)

run:
	@go run ./src -addr :8080

clean:
	rm -rf bin
