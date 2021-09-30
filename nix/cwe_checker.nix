{ version
, changelog
, downloadPage
, homepage
, maintainers
, platforms
}:
{ lib
, fenix
, ghidra-bin
, makeRustPlatform
, makeWrapper
, nix-filter
, writeShellScript
, ...
}:

let
  inherit (nix-filter) inDirectory;

  rustToolchain = fenix.stable;
  rustPlatform = makeRustPlatform {
    inherit (rustToolchain) cargo rustc;
  };

  pname = "cwe_checker";
  root = ./..;
  # Reading the files in the filtered directory is not possible right now.
  # Follow up on how https://github.com/NixOS/nix/pull/5163 will be resolved.
  mainProgram = pname;

  src = nix-filter {
    inherit root;
    name = pname;
    include = [
      "Cargo.lock"
      "Cargo.toml"
      (inDirectory "src")
      (inDirectory "test")
    ];
  };

  preRunScript = writeShellScript "preRunScript" ''
    config_dir="$HOME/.config/cwe_checker"
    config_json="$config_dir/config.json"
    if [[ ! -f $config_json ]]; then
      install --mode=644 -D ${toString src}/src/config.json $config_json
    fi

    ghidra_json="$config_dir/ghidra.json"
    if [[ ! -f $ghidra_json ]]; then
      echo '{ "ghidra_path": "${ghidra-bin}/lib/ghidra" }' > $ghidra_json
    fi
  '';
in
rustPlatform.buildRustPackage {
  inherit pname version src;

  cargoHash = "sha256-igAygYTIkV+gfBWVHGVspheTC19TilU3A3/MqSwhd90=";

  buildInputs = [
    ghidra-bin.out
  ];

  nativeBuildInputs = [
    makeWrapper.out
  ];

  patches = [
    ./patches/0001-use-env-variable-for-ghidra-plugin-path.patch
  ];

  postInstall = ''
    wrapProgram "$out/bin/${mainProgram}" \
      --set CWE_CHECKER_GHIDRA_PLUGIN_PATH "${toString src}/src/ghidra" \
      --run ${preRunScript}
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    tmp=$(mktemp)
    HOME=$(mktemp -d) # because of the preRunScript
    $out/bin/${mainProgram} --version &> $tmp || (cat $tmp; exit 1)
    echo "OK"
  '';

  passthru = {
    inherit rustToolchain;
    ghidra_plugin = "${toString root}/ghidra_plugin/cwe_checker_ghidra_plugin.py";
  };

  meta = {
    description = "cwe_checker finds vulnerable patterns in binary executables";
    longDescription =
      "cwe_checker is a suite of checks to detect common bug classes such as" +
      "use of dangerous functions and simple integer overflows. These bug" +
      "classes are formally known as Common Weakness Enumerations (CWEs). Its" +
      "main goal is to aid analysts to quickly find vulnerable code paths.";

    inherit homepage downloadPage changelog;

    license = lib.licenses.lgpl3Plus;
    inherit maintainers mainProgram platforms;
  };
}
