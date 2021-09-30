{
  description = "cwe_checker finds vulnerable patterns in binary executables";

  inputs = {
    # use upstream once https://github.com/NixOS/nixpkgs/pull/140208 is accepted
    # nixpkgs.url = "nixpkgs/nixos-21.05";
    nixpkgs.url = "github:ilkecan/nixpkgs/nixos-21.05";
    flake-utils.url = "github:numtide/flake-utils";
    nix-filter.url = "github:numtide/nix-filter";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nix-utils = {
      url = "git+https://git.sr.ht/~ilkecan/nix-utils";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    let
      inherit (builtins)
        attrNames
        attrValues
      ;
      inherit (nixpkgs.lib)
        getAttrs
        intersectLists
      ;
      inherit (flake-utils.lib)
        defaultSystems
        eachSystem
      ;
      nix-filter = inputs.nix-filter.lib;
      nix-utils = inputs.nix-utils.lib;
      inherit (nix-utils)
        createOverlays
        importCargoLock
      ;

      # ghidra-bin.meta.platforms
      ghidraPlatforms = [ "x86_64-linux" "x86_64-darwin" ];
      supportedSystems = intersectLists defaultSystems ghidraPlatforms;
      commonArgs = {
        version = (importCargoLock ./.).cwe_checker.version;
        homepage = "https://github.com/fkie-cad/cwe_checker";
        downloadPage = "https://github.com/fkie-cad/cwe_checker/releases";
        changelog = "https://raw.githubusercontent.com/fkie-cad/cwe_checker/master/CHANGES.md";
        maintainers = [
          {
            email = "ilkecan@protonmail.com";
            github = "ilkecan";
            githubId = 40234257;
            name = "ilkecan bozdogan";
          }
        ];
        platforms = supportedSystems;
      };

      derivations = {
        cwe_checker = import ./nix/cwe_checker.nix commonArgs;
        cwe_checker_to_ida = import ./nix/cwe_checker_to_ida.nix commonArgs;
      };
    in
    {
      overlays = createOverlays derivations {
        inherit
          nix-filter
          nix-utils
        ;
      };
      overlay = self.overlays.cwe_checker;
    } // eachSystem supportedSystems (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = attrValues self.overlays ++ [
            inputs.fenix.overlay
          ];
        };

        packageNames = attrNames derivations;
      in
      rec {
        checks = packages;

        packages = getAttrs packageNames pkgs;
        defaultPackage = packages.cwe_checker;

        hydraJobs = {
          build = packages;
        };

        devShell =
          let
            packageList = attrValues packages;
          in
          pkgs.mkShell {
            packages = packageList ++ [
              defaultPackage.rustToolchain.defaultToolchain
            ];
            inputsFrom = packageList;
          };
      });
}
