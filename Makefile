.PHONY: web test build release clean

VERSION ?= 0.1.0
export GOTOOLCHAIN := go1.26.5

web:
	cd web && npm ci && npm run build

test:
	go test ./...
	cd web && npm run build
	sh -n install.sh uninstall.sh compat/deploy-hy2.sh

build: web
	mkdir -p build
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o build/wukong-panel ./cmd/wukong-panel

release: web
	./scripts/build-release.sh $(VERSION)

clean:
	rm -rf build release
