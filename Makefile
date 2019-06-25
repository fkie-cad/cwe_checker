.PHONY: all clean test uninstall docker
all:
	dune build
	dune install
	cd plugins/cwe_checker; make all; cd ../..
	cd plugins/cwe_checker_emulation; make all; cd ../..
	cd plugins/cwe_checker_type_inference; make all; cd ../..
	cd plugins/cwe_checker_type_inference_print; make all; cd ../..

test:
	dune runtest
	cd test/artificial_samples; scons; cd ../..
	pytest -v

clean:
	dune clean
	bapbuild -clean
	cd test/unit; make clean; cd ../..
	cd plugins/cwe_checker; make clean; cd ../..
	cd plugins/cwe_checker_emulation; make clean; cd ../..
	cd plugins/cwe_checker_type_inference; make clean; cd ../..
	cd plugins/cwe_checker_type_inference_print; make clean; cd ../..

uninstall:
	dune uninstall
	cd plugins/cwe_checker; make uninstall; cd ../..
	cd plugins/cwe_checker_emulation; make uninstall; cd ../..
	cd plugins/cwe_checker_type_inference; make uninstall; cd ../..
	cd plugins/cwe_checker_type_inference_print; make uninstall; cd ../..

docker:
	./install.sh
