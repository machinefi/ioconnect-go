## build all targets to ./build/
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
