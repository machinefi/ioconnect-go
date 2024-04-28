.PHONY: build
build:
	@CGO_LDFLAGS='-L../../pkg/ioconnect/lib/linux-x86_64 -lioConnectCore' go build  .

.PHONY: run
run: build
	@./srv-did-vc