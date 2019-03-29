.PHONY: all clean test uninstall
all:
	dune build --profile release
	dune install
	cd plugins/cwe_checker; make all; cd ../..
	cd plugins/cwe_type_inference; make all; cd ../..

test:
	dune runtest --profile release # TODO: correct all dune linter warnings so that we can remove --profile release
	pytest -v

clean:
	dune clean
	bapbuild -clean
	cd plugins/cwe_checker; make clean; cd ../..
	cd plugins/cwe_type_inference; make clean; cd ../..

uninstall:
	dune uninstall
	cd plugins/cwe_checker; make uninstall; cd ../..
	cd plugins/cwe_type_inference; make uninstall; cd ../..
