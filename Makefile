.PHONY: all clean test uninstall docker
all:
	cargo build --release
	cp target/release/libcwe_checker_rs.a src/libcwe_checker_rs.a
	cp target/release/libcwe_checker_rs.so src/dllcwe_checker_rs.so
	dune build
	dune install
	cd plugins/cwe_checker && make all
	cd plugins/cwe_checker_emulation && make all
	cd plugins/cwe_checker_type_inference && make all
	cd plugins/cwe_checker_type_inference_print && make all
	cd plugins/cwe_checker_pointer_inference_debug && make all
	mkdir -p ${HOME}/.config/cwe_checker
	cp src/utils/registers.json ${HOME}/.config/cwe_checker/registers.json

test:
	cargo test
	cd test/unit/ && ./specify_test_files_for_compilation.sh
	dune runtest
	cd test/artificial_samples; scons; cd ../..
	pytest -v --ignore=_build

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
	dune uninstall
	cd plugins/cwe_checker; make uninstall; cd ../..
	cd plugins/cwe_checker_emulation; make uninstall; cd ../..
	cd plugins/cwe_checker_type_inference; make uninstall; cd ../..
	cd plugins/cwe_checker_type_inference_print; make uninstall; cd ../..
	cd plugins/cwe_checker_pointer_inference_debug; make uninstall; cd ../..
	rm -f -r ${HOME}/.config/cwe_checker

documentation:
	dune build @doc
	cp -r _build/default/_doc/_html doc/html

docker:
	./install.sh
