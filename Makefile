.RECIPEPREFIX := >
TARGETS := $(shell ls scripts)

DAPPER_IMAGE ?= pasturestack-authentication-service-dapper:ubuntu26
DAPPER_HOST_ARCH ?= amd64
DAPPER_SOURCE ?= /go/src/github.com/PastureStack/authentication-service

.dapper:
>docker build \
>  --network "$${DOCKER_BUILD_NETWORK:-host}" \
>  --build-arg DAPPER_HOST_ARCH=$(DAPPER_HOST_ARCH) \
>  -t $(DAPPER_IMAGE) \
>  -f Dockerfile.dapper .

$(TARGETS): .dapper
>docker run --rm \
>  --user "$$(id -u):$$(id -g)" \
>  -v $(CURDIR):$(DAPPER_SOURCE) \
>  -e ARCH=$(DAPPER_HOST_ARCH) \
>  -e TAG \
>  -e DOCKER_BUILD_NETWORK \
>  -e VERSION_OVERRIDE \
>  $(DAPPER_IMAGE) $@

trash: deps

trash-keep: deps

deps: vendor

.DEFAULT_GOAL := ci

.PHONY: .dapper $(TARGETS) trash trash-keep deps
