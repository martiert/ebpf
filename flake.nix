{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }: 
  flake-utils.lib.eachDefaultSystem (system: let
    pkgs = import nixpkgs { inherit system; };
  in rec {
    packages = {
      presentation = pkgs.callPackage ./presentation {
        date = toString self.lastModified;
      };
      presenter = pkgs.writeShellScriptBin "present" ''
        ${pkgs.beamerpresenter}/bin/beamerpresenter ${packages.presentation}/ebpf.pdf
      '';
      default = packages.presenter;
    };
    devShells = {
      default = pkgs.mkShell {
        packages = with pkgs; [
          gnumake
          clang

          libbpf
          libelf
          bpftools
          fmt.dev

          pkg-config
        ];
      };
      presentation = pkgs.mkShell {
        inputsFrom = [ packages.presentation ];
        packages = [ pkgs.beamerpresenter ];
      };
    };
  });
}
