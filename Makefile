.PHONY: all clean test uninstall
all:
	cd src; bapbuild -r -Is checkers,utils -pkgs yojson,unix cwe_checker.plugin; bapbundle install cwe_checker.plugin; cd ..

test:
	pytest -v

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_checker.plugin
