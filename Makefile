.PHONY: build install install-service install-docker doctor test lint check

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

check:
	./scripts/check.sh

test:
	cargo run --quiet -- lint --dir .
	cargo test --all-features --target-dir target/unit-tests

lint:
	cargo run --quiet -- lint --dir .
