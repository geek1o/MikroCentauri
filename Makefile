GO ?= .cache/go/bin/go
SB_PLATFORM := $(shell uname -s | tr A-Z a-z)-$(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
SING_BOX ?= $(CURDIR)/.cache/sing-box-1.14.2-$(SB_PLATFORM)/sing-box

.PHONY: bootstrap test smoke check prototype cross-build probe
bootstrap:
	python3 scripts/bootstrap-tools.py
test:
	SING_BOX_BINARY="$(SING_BOX)" $(GO) test -race ./...
	$(GO) vet ./...
	python3 tests/integration/lab_switch.py
	python3 tests/integration/app_image.py
	python3 tests/integration/release_artifacts.py
	python3 tests/integration/release_sbom.py
smoke:
	python3 tests/integration/namespace_policy.py --sing-box "$(SING_BOX)"
	python3 tests/integration/binding_policy.py --sing-box "$(SING_BOX)"
	python3 tests/integration/smoke.py --go "$(GO)" --sing-box "$(SING_BOX)"
check: test smoke webui-check
	git diff --check
prototype:
	$(GO) run ./cmd/mikrocentauri generate -config lab/configs/hybrid.json -out .cache/candidate.json -sing-box "$(SING_BOX)"
	$(GO) run ./cmd/mikrocentauri plan -config lab/configs/hybrid.json
cross-build:
	mkdir -p .cache/bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' -o .cache/bin/mikrocentauri-linux-amd64 ./cmd/mikrocentauri
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build ./internal/...
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o .cache/bin/mikrocentauri-linux-arm64 ./cmd/mikrocentauri
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build ./internal/...
probe:
	python3 scripts/build-probe.py --go "$(GO)"

.PHONY: dataplane-lab quic-test
dataplane-lab:
	python3 scripts/prepare-dataplane-lab.py
quic-test:
	cd lab/quic && $(abspath $(GO)) test -race ./... && $(abspath $(GO)) vet ./...

.PHONY: webui webui-check webui-test
webui:
	python3 scripts/build-webui.py
webui-check:
	python3 scripts/build-webui.py --check
webui-test:
	SING_BOX_BINARY="$(SING_BOX)" python3 scripts/test-webui.py

.PHONY: app-image app-image-check
app-image:
	python3 scripts/build-app-image.py --go "$(GO)"
app-image-check:
	python3 scripts/verify-app-image.py

.PHONY: release-candidate release-candidate-check
RC_DIRECTORY ?= .cache/releases/v0.1.0-rc.1
release-candidate:
	python3 scripts/build-release.py --go "$(GO)" --output "$(RC_DIRECTORY)"
release-candidate-check:
	python3 scripts/build-release.py --verify "$(RC_DIRECTORY)"
