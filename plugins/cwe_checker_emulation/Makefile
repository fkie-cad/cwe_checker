all:
	bapbuild -pkgs yojson,unix,ppx_jane,bap-primus,monads,graphlib,str,cwe_checker_core cwe_checker_emulation.plugin
	bapbundle install cwe_checker_emulation.plugin

clean:
	bapbuild -clean

uninstall:
	bapbundle remove cwe_checker_emulation.plugin
