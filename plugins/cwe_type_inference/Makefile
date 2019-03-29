all:
	bapbuild -pkgs yojson,unix,ppx_jane,cwe_checker_core cwe_type_inference.plugin
	bapbundle install cwe_type_inference.plugin

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_type_inference.plugin
