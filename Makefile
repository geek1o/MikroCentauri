GO ?= .cache/go/bin/go
SB_PLATFORM := $(shell uname -s | tr A-Z a-z)-$(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
SING_BOX ?= $(CURDIR)/.cache/sing-box-1.14.2-$(SB_PLATFORM)/sing-box

.PHONY: bootstrap test smoke check prototype cross-build probe
bootstrap:
	python3 scripts/bootstrap-tools.py
test:
	SING_BOX_BINARY="$(SING_BOX)" $(GO) test -race ./...
	$(GO) vet ./...
smoke:
	python3 tests/integration/smoke.py --go "$(GO)" --sing-box "$(SING_BOX)"
check: test smoke
	git diff --check
prototype:
	$(GO) run ./cmd/mikrocentauri generate -config lab/configs/hybrid.json -out .cache/candidate.json -sing-box "$(SING_BOX)"
	$(GO) run ./cmd/mikrocentauri plan -config lab/configs/hybrid.json
cross-build:
	mkdir -p .cache/bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags='-s -w' -o .cache/bin/mikrocentauri-linux-amd64 ./cmd/mikrocentauri
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags='-s -w' -o .cache/bin/mikrocentauri-linux-arm64 ./cmd/mikrocentauri
probe:
	python3 scripts/build-probe.py --go "$(GO)"
