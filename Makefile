## build all targets to ./build/
MOD=$(shell cat go.mod | grep ^module -m 1 | awk '{ print $$2; }' || '')

.PHONY: targets
targets:
	@cd cmd && for target in * ; \
	do \
		echo "\033[32mbuilding $$target ... \033[0m" ; \
		if [ -d $$target ] && [ -e $$target/Makefile ]; then \
			cd $$target; \
			make build --no-print-directory; \
			cd ..; \
		else \
			echo "\033[31mno entry\033[0m" ; \
		fi; \
		echo "\033[32mdone!\033[0m\n"; \
	done

.PHONY: images
images:
	@cd cmd && for target in * ; \
	do \
		echo "\033[32mbuilding $$target docker image ... \033[0m" ; \
		if [ -d $$target ] && [ -e $$target/Dockerfile ]; then \
			cd $$target; \
			make image --no-print-directory || true; \
			cd ..; \
		else \
			echo "\033[31mno entry\033[0m" ; \
		fi; \
		echo "\033[32mdone!\033[0m\n"; \
	done

.PHONY: fmt
fmt:
	@if [ -z $$MOD ]; then \
		goimports -w . ; \
	else \
		goimports -w -local "${MOD}" . ; \
	fi

.PHONY: test
test:
	@CGO_LDFLAGS='-L./pkg/ioconnect/lib/linux-x86_64 -lioConnectCore' go test ./... -v -covermode=atomic -coverprofile cover.out



