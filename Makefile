GHIDRA_PATH =

.PHONY: all clean test uninstall docker
all:
	cargo build --release
ifdef GHIDRA_PATH
	mkdir -p ${HOME}/.config/cwe_checker
	cp src/config.json ${HOME}/.config/cwe_checker/config.json
	cargo install --path src/caller --locked
	echo "{ \"ghidra_path\": \"${GHIDRA_PATH}\" }" > ${HOME}/.config/cwe_checker/ghidra.json
	mkdir -p ${HOME}/.local/share/cwe_checker
	cp -r src/ghidra ${HOME}/.local/share/cwe_checker/ghidra
else
	echo "GHIDRA_PATH not specified. Please set it to the path to your local Ghidra installation."
	false
endif

test:
	cargo test
	if [ ! -d "test/artificial_samples/build" ]; then \
		echo "Acceptance test binaries not found. Please see test/artificial_samples/Readme.md for build instructions."; \
		exit -1; \
	fi
	cargo test --no-fail-fast -p acceptance_tests_ghidra -- --show-output --ignored

compile_test_files:
	cd test/artificial_samples \
	&& docker build -t cross_compiling . \
	&& docker run --rm -v $(pwd)/build:/home/cwe/artificial_samples/build cross_compiling sudo /home/cwe/.local/bin/scons

codestyle-check:
	cargo fmt -- --check
	cargo clippy -- -D clippy::all -D missing_docs

clean:
	cargo clean
	rm -f -r doc/html

uninstall:
	rm -f -r ${HOME}/.config/cwe_checker
	rm -f -r ${HOME}/.local/share/cwe_checker
	cargo uninstall cwe_checker

documentation:
	cargo doc --open --no-deps

docker:
	make clean
	docker build -t cwe_checker .
