.phony: all
all:
	cd src; bapbuild -r -Is checkers,utils -pkgs yojson,unix cwe_checker.plugin; bapbundle install cwe_checker.plugin; cd ..

test:
	bapbuild -r -Is src,src/checkers,src/utils,test -pkgs yojson,unix,alcotest test/test_cwe_checker.byte
	./test/test_cwe_checker.byte

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_checker.plugin
