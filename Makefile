GO ?= .cache/go/bin/go
SB_PLATFORM := $(shell uname -s | tr A-Z a-z)-$(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
SING_BOX ?= $(CURDIR)/.cache/sing-box-1.14.2-$(SB_PLATFORM)/sing-box

.PHONY: bootstrap test smoke check cross-build webui webui-check webui-test app-image app-image-check package
bootstrap:
	python3 scripts/bootstrap-tools.py
test:
	SING_BOX_BINARY="$(SING_BOX)" $(GO) test -race ./...
	$(GO) vet ./...
	python3 tests/integration/app_image.py
	python3 tests/integration/release_sbom.py
	python3 tests/integration/alpine_sources.py
	python3 scripts/ci-test-publication.py
smoke:
	python3 tests/integration/namespace_policy.py --sing-box "$(SING_BOX)"
	python3 tests/integration/binding_policy.py --sing-box "$(SING_BOX)"
	python3 tests/integration/smoke.py --go "$(GO)" --sing-box "$(SING_BOX)"
check: test smoke webui-check
	git diff --check
cross-build:
	mkdir -p .cache/bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -buildvcs=false -trimpath -o .cache/bin/mikrocentauri-linux-amd64 ./cmd/mikrocentauri
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -buildvcs=false -trimpath -o .cache/bin/mikrocentauri-linux-arm64 ./cmd/mikrocentauri
webui:
	python3 scripts/build-webui.py
webui-check:
	python3 scripts/build-webui.py --check
webui-test:
	SING_BOX_BINARY="$(SING_BOX)" python3 scripts/test-webui.py
app-image:
	python3 scripts/build-distributable-image.py --go "$(GO)"
app-image-check:
	python3 scripts/verify-app-image.py
package:
	python3 scripts/ci-package.py
