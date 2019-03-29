.PHONY: all clean test uninstall
all:
	cd cwe_checker_static; bapbuild -r -Is checkers,utils -pkgs yojson,unix cwe_checker_static.plugin; bapbundle install cwe_checker_static.plugin; cd ..
	cd cwe_checker_emulation; bapbuild -pkgs bap-primus,monads,graphlib,ppx_jane,str cwe_checker_emulation.plugin; bapbundle install cwe_checker_emulation.plugin; cd ..
test:
	pytest -v

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_checker_static.plugin
	bapbundle remove cwe_checker_emulation.plugin
