{ version
, changelog
, downloadPage
, homepage
, maintainers
, platforms
}:
{ lib
, python3
, stdenvNoCC
, ...
}:

let
  python = python3;
  mainProgram = "cwe_checker_to_ida.py";
in
stdenvNoCC.mkDerivation {
  pname = "cwe_checker_to_ida";
  inherit version;

  src = ./../cwe_checker_to_ida;

  outputs = [ "bin" "out" ];
  propagatedBuildOutputs = [ ];

  strictDeps = true;

  buildInputs = [
    python
  ];

  nativeBuildInputs = [
    python
  ];

  patches = [
    ./patches/0002-add-shebang-to-cwe-checher-to-ida.patch
  ];

  dontConfigure = true;
  dontBuild = true;

  doCheck = true;
  checkPhase = ''
    python -m unittest CweCheckerParser_test.py
  '';

  installPhase = ''
    mkdir -p $bin/bin
    cp -r . $bin/lib
    chmod +x $bin/lib/cwe_checker_to_ida.py
    ln -s $bin/lib/${mainProgram} $bin/bin/${mainProgram}

    mkdir $out
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    tmp=$(mktemp)
    $bin/bin/${mainProgram} -h &> $tmp || (cat $tmp; exit 1)
    echo "OK"
  '';

  meta = {
    description =
      "Generates an anotation script for IDA Pro based on CweChecker results";

    inherit homepage downloadPage changelog;

    license = lib.licenses.lgpl3Plus;
    inherit maintainers mainProgram platforms;
  };
}
