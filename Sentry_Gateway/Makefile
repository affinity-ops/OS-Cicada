.PHONY: sbom vulncheck build-sidecar-all build-sidecar-linux build-sidecar-mac build-sidecar-win proto-eakf build-eakfd test

proto-eakf:
	@echo "Compiling eakf.proto..."
	PATH="$$PATH:$$(go env GOPATH)/bin" protoc \
		--go_out=. --go_opt=module=github.com/asai/cicada/sentry \
		--go-grpc_out=. --go-grpc_opt=module=github.com/asai/cicada/sentry \
		pkg/eakf/v1/eakf.proto
	@echo "Generated Go stubs in pkg/eakf/v1/"

build-eakfd:
	@echo "Building eakfd daemon..."
	go build -o eakfd ./cmd/eakfd
	@echo "Built: ./eakfd"

test:
	@echo "Running full test suite..."
	go test ./... -count=1

sbom:
	@echo "Generating CycloneDX SBOM..."
	cyclonedx-gomod mod -output sbom.json

vulncheck:
	@echo "Running govulncheck for known vulnerabilities..."
	govulncheck ./...

build-sidecar-all: build-sidecar-linux build-sidecar-mac build-sidecar-win

build-sidecar-linux:
	@echo "Building Sidecar for Linux (amd64/arm64)..."
	mkdir -p release/
	GOOS=linux GOARCH=amd64 go build -o release/cicada-sidecar-linux-amd64 ./cmd/sidecar
	GOOS=linux GOARCH=arm64 go build -o release/cicada-sidecar-linux-arm64 ./cmd/sidecar

build-sidecar-mac:
	@echo "Building Sidecar for macOS (arm64/amd64)..."
	mkdir -p release/
	GOOS=darwin GOARCH=arm64 go build -o release/cicada-sidecar-darwin-arm64 ./cmd/sidecar
	GOOS=darwin GOARCH=amd64 go build -o release/cicada-sidecar-darwin-amd64 ./cmd/sidecar

build-sidecar-win:
	@echo "Building Sidecar for Windows (amd64)..."
	mkdir -p release/
	GOOS=windows GOARCH=amd64 go build -o release/cicada-sidecar-windows-amd64.exe ./cmd/sidecar
