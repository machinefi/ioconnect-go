VERSION=$(shell git describe --tags --always)
FEATURE=$(shell git branch | grep '*' | awk '{ print $$2; }')
BUILD_TIME=$(shell date +%Y%m%d%H%M%S)
VERSION_PATH=github.com/machinefi/ioconnect-go/cmd/srv-did-vc
REPO_ROOT=../..

.PHONY: debug
debug:
	@echo ${FEATURE}
	@echo ${VERSION}
	@echo ${BUILD_TIME}
	@echo ${BUILD_ROOT}

.PHONY: build
build:
	@CGO_LDFLAGS='-L../../pkg/ioconnect/lib/linux-x86_64 -lioConnectCore' go build -ldflags \
	"-X ${VERSION_PATH}.Name=srv-did-vc\
	-X ${VERSION_PATH}.Feature=${FEATURE}\
	-X ${VERSION_PATH}.Timestamp=${BUILD_TIME}\
	-X ${VERSION_PATH}.Version=${VERSION}"


.PHONY: run
run: build
	@./srv-did-vc

.PHONY: clean
clean:
	@rm -rf srv-did-vc