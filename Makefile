IMAGE := xconnio/deskconn-router
VERSION := $(shell git describe --tags --always)
export CGO_ENABLED := 1

ifdef XCONN_SDK_DIR
export PKG_CONFIG_PATH := $(abspath $(XCONN_SDK_DIR))/lib/pkgconfig$(if $(PKG_CONFIG_PATH),:$(PKG_CONFIG_PATH))
endif

.PHONY: native-check native-sdk build-static
native-check:
	@pkg-config --exists xconn || (echo "Run make native-sdk once; see README.md"; exit 1)

native-sdk:
	@set -e; script=$$(mktemp); \
	trap 'rm -f "$$script"' EXIT; \
	curl -fLsS https://raw.githubusercontent.com/xconnio/xconn/v0.1.6/scripts/install-xconn-sdk.sh -o "$$script"; \
	sh "$$script"

test: native-check
	go test -count=1 ./... -v

lint:
	golangci-lint run

build: native-check
	go build github.com/xconnio/deskconn-router/cmd/deskconn-router

build-static: native-check
	@test "$$(uname -s)" = Linux || (echo "Fully static builds support Linux only"; exit 1)
	go build -tags xconn_static,netgo,osusergo -ldflags "-s -w -linkmode external -extldflags '-static -Wl,--gc-sections'" github.com/xconnio/deskconn-router/cmd/deskconn-router

run: native-check
	go run github.com/xconnio/deskconn-router/cmd/deskconn-router

DOCKER_BUILD := docker buildx build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest

build-docker:
	$(DOCKER_BUILD) --platform linux/amd64,linux/arm64 .

build-docker-amd64:
	$(DOCKER_BUILD) --platform linux/amd64 .

build-docker-arm64:
	$(DOCKER_BUILD) --platform linux/arm64 .

push-docker:
	@[ "$$CI" = true ] || { echo "push-docker only runs in CI"; exit 1; }
	$(DOCKER_BUILD) --platform linux/amd64,linux/arm64 --push .

run-docker:
	docker compose up
