VERSION=$(shell git describe --tags --always)
FEATURE=$(shell git branch --show-current)
COMMIT_ID=$(shell git rev-parse --short HEAD)
BUILD_TIME=$(shell TZ=Asia/Shanghai date +%Y-%m-%dT%H:%M:%S+08:00)
VERSION_PATH=main
TARGET=srv-did-vc
REPO_ROOT=../..

.PHONY: debug
debug:
	@echo ${FEATURE}
	@echo ${VERSION}
	@echo ${COMMIT_ID}
	@echo ${BUILD_TIME}

.PHONY: build_static
build_static:
	@CGO_ENABLED=1 CGO_LDFLAGS='-L../../pkg/ioconnect/lib/linux-x86_64 -lioConnectCore' go build \
  -ldflags "-s -w -extldflags '-static'          \
	-X '${VERSION_PATH}.Name=${TARGET}'          \
	-X '${VERSION_PATH}.Feature=${FEATURE}'      \
	-X '${VERSION_PATH}.CommitID=${COMMIT_ID}'   \
	-X '${VERSION_PATH}.Timestamp=${BUILD_TIME}' \
	-X '${VERSION_PATH}.Version=${VERSION}' "    \
  -o ${TARGET}_static

.PHONE: build_shared
build_shared:
	@CGO_ENABLED=1 CGO_LDFLAGS='-L../../pkg/ioconnect/lib/linux-x86_64 -lioConnectCore' go build \
	-ldflags "-s -w                              \
	-X '${VERSION_PATH}.Name=${TARGET}'          \
	-X '${VERSION_PATH}.Feature=${FEATURE}'      \
	-X '${VERSION_PATH}.Timestamp=${BUILD_TIME}' \
	-X '${VERSION_PATH}.Version=${VERSION}' "    \
	-o ${TARGET}_shared

.PHONE: build
build: build_static
	@mv ${TARGET}_static ${TARGET}

.PHONY: image
image:
	@cd ${REPO_ROOT} && docker build -f cmd/srv-did-vc/Dockerfile . -t $(USER)/srv-did-vc:${VERSION}

.PHONY: run
run: build
	@./${TARGET}

.PHONY: clean
clean:
	@rm -rf ${TARGET}*
