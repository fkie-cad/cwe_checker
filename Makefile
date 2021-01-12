GHIDRA_PATH =

.PHONY: all clean test uninstall docker
all:
	cargo build --release
	mkdir -p ${HOME}/.config/cwe_checker
	cp src/config.json ${HOME}/.config/cwe_checker/config.json
ifdef GHIDRA_PATH
	cargo install --path caller --locked
	echo "{ \"ghidra_path\": \"${GHIDRA_PATH}\" }" > ${HOME}/.config/cwe_checker/ghidra.json
	mkdir -p ${HOME}/.local/share/cwe_checker
	cp -r ghidra ${HOME}/.local/share/cwe_checker/ghidra
else
	cp target/release/libcwe_checker_rs.a src/libcwe_checker_rs.a
	cp target/release/libcwe_checker_rs.so src/dllcwe_checker_rs.so
	dune build
	dune install
	cd plugins/cwe_checker && make all
	cd plugins/cwe_checker_emulation && make all
	cd plugins/cwe_checker_type_inference && make all
	cd plugins/cwe_checker_type_inference_print && make all
	cd plugins/cwe_checker_pointer_inference_debug && make all
endif

test:
	cargo test
ifeq (,$(wildcard ${HOME}/.config/cwe_checker/ghidra.json))
	cd test/unit/ && ./specify_test_files_for_compilation.sh
	dune runtest
	cd test/artificial_samples; scons; cd ../..
	pytest -v --ignore=_build
else
	cd test/artificial_samples; scons; cd ../..
	cargo test --no-fail-fast -p acceptance_tests_ghidra -- --show-output --ignored
endif

compile_test_files:
	cd test/artificial_samples \
	&& docker build -t cross_compiling . \
	&& docker run --rm -v $(pwd)/build:/home/cwe/artificial_samples/build cross_compiling sudo /home/cwe/.local/bin/scons

codestyle-check:
	cargo fmt -- --check
	cargo clippy -- -D clippy::all

clean:
	cargo clean
	rm -f src/libcwe_checker_rs.a
	rm -f src/dllcwe_checker_rs.so
	dune clean
	bapbuild -clean
	rm -f -r doc/html
	cd test/unit; make clean; cd ../..
	cd plugins/cwe_checker; make clean; cd ../..
	cd plugins/cwe_checker_emulation; make clean; cd ../..
	cd plugins/cwe_checker_type_inference; make clean; cd ../..
	cd plugins/cwe_checker_type_inference_print; make clean; cd ../..
	cd plugins/cwe_checker_pointer_inference_debug; make clean; cd ../..

uninstall:
	rm -f -r ${HOME}/.config/cwe_checker
	rm -f -r ${HOME}/.local/share/cwe_checker
	cargo uninstall cwe_checker; echo ""
	dune uninstall
	cd plugins/cwe_checker; make uninstall; cd ../..
	cd plugins/cwe_checker_emulation; make uninstall; cd ../..
	cd plugins/cwe_checker_type_inference; make uninstall; cd ../..
	cd plugins/cwe_checker_type_inference_print; make uninstall; cd ../..
	cd plugins/cwe_checker_pointer_inference_debug; make uninstall; cd ../..

documentation:
	dune build @doc
	cp -r _build/default/_doc/_html doc/html

docker:
	./install.sh
