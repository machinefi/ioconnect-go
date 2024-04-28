VERSION=$(shell git describe --tags --always)
FEATURE=$(shell git branch | grep '*' | awk '{ print $$2; }')
BUILD_TIME=$(shell date +%Y%m%d%H%M%S)
VERSION_PATH=github.com/machinefi/ioconnect/cmd
#VERSION_PATH=main
TARGET=srv-did-vc
REPO_ROOT=../..

.PHONY: debug
debug:
	@echo ${FEATURE}
	@echo ${VERSION}
	@echo ${BUILD_TIME}

.PHONY: build
build:
	CGO_LDFLAGS='-L../../pkg/ioconnect/lib/linux-x86_64 -lioConnectCore' go build -ldflags \
	"-X ${VERSION_PATH}.Name=${TARGET} \
	-X ${VERSION_PATH}.Feature=${FEATURE} \
	-X ${VERSION_PATH}.Timestamp=${BUILD_TIME} \
	-X ${VERSION_PATH}.Version=${VERSION}" -o ${TARGET}


.PHONY: run
run: build
	@./${TARGET}

.PHONY: clean
clean:
	@rm -rf ${TARGET}