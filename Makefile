.PHONY: web test build release clean

VERSION ?= 0.9.2
export GOTOOLCHAIN := go1.26.5

web:
	cd web && npm ci && npm run build

test:
	go test ./...
	go vet ./...
	cd web && npm run build
	sh -n install.sh uninstall.sh bootstrap.sh compat/deploy-hy2.sh
	sh scripts/test-install-actions.sh
	sh scripts/test-install-hardening.sh
	sh scripts/test-install-residential-dependencies.sh
	sh scripts/test-install-residential-peer-install.sh
	sh scripts/test-install-residential-peer-remove.sh
	sh scripts/test-install-acme-status.sh
	sh scripts/test-install-cert-renewal.sh
	sh scripts/test-install-subscription-domain.sh
	sh scripts/test-install-tls-backfill.sh
	sh scripts/test-singbox-lifecycle.sh

build: web
	mkdir -p build
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o build/wukong-panel ./cmd/wukong-panel

release: web
	./scripts/build-release.sh $(VERSION)

clean:
	rm -rf build release
