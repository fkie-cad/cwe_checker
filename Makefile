GHIDRA_PATH =

.PHONY: all clean test uninstall docker
all:
	cargo build -p cwe_checker_install --release
	./target/release/cwe_checker_install ${GHIDRA_PATH}

test:
	cargo test
	if [ ! -d "test/artificial_samples/build" ]; then \
		echo "Acceptance test binaries not found. Please see test/artificial_samples/Readme.md for build instructions."; \
		exit -1; \
	fi
	cargo test --no-fail-fast -p acceptance_tests_ghidra -- --show-output --ignored --test-threads 1

compile_test_files:
	cd test/artificial_samples \
	&& docker build -t cross_compiling . \
	&& docker run --rm -v $(pwd)/build:/home/cwe/artificial_samples/build cross_compiling sudo /home/cwe/.local/bin/scons

codestyle-check:
	cargo fmt -- --check
	cargo clippy -- -D clippy::all -D missing_docs
	RUSTDOCFLAGS="-Dwarnings" cargo doc --no-deps --document-private-items

clean:
	cargo clean
	rm -f -r doc/html

uninstall:
	cargo build -p cwe_checker_install --release
	./target/release/cwe_checker_install --uninstall

documentation:
	cargo doc --open --no-deps

docker:
	make clean
	docker build -t cwe_checker .
