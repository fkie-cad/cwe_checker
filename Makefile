.PHONY: all clean test uninstall
all:
	cd src; bapbuild -r -Is checkers,utils,analysis -pkgs yojson,unix cwe_checker.plugin; bapbundle install cwe_checker.plugin; cd ..

test:
	dune runtest --profile release # TODO: correct all dune linter warnings so that we can remove --profile release
	pytest -v

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_checker.plugin
