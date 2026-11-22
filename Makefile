.PHONY: build install install-service install-docker doctor test lint

build:
	./scripts/build-release.sh

install:
	./scripts/install.sh

install-service:
	./scripts/install.sh --service

install-docker:
	./scripts/install.sh --docker

doctor:
	cargo run -- doctor

test:
	python3 scripts/security-lint.py
	cargo test --target-dir target/unit-tests

lint:
	python3 scripts/security-lint.py
