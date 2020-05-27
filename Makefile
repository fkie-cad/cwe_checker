.PHONY: all clean test uninstall docker
all:
	cargo build --release
	cp target/release/libcwe_checker_rs.a src/libcwe_checker_rs.a
	cp target/release/libcwe_checker_rs.so src/dllcwe_checker_rs.so
	dune build
	dune install
	cd plugins/cwe_checker; make all; cd ../..
	cd plugins/cwe_checker_emulation; make all; cd ../..
	cd plugins/cwe_checker_type_inference; make all; cd ../..
	cd plugins/cwe_checker_type_inference_print; make all; cd ../..
	cd plugins/cwe_checker_pointer_inference_debug; make all; cd ../..

test:
	cargo test
	dune runtest
	cd test/artificial_samples; scons; cd ../..
	pytest -v --ignore=_build

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

documentation:
	dune build @doc
	cp -r _build/default/_doc/_html doc/html

docker:
	./install.sh
