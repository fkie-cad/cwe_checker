all:
	bapbuild -pkgs yojson,unix,ppx_jane,cwe_checker_core cwe_checker.plugin
	bapbundle install cwe_checker.plugin

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_checker.plugin
