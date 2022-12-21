{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShell = pkgs.stdenv.mkDerivation {
        name = "shell";
        SYSTEMD_DEBUGGER = "lldb";
        nativeBuildInputs = with pkgs; [cmake pkg-config ninja lldb];
        buildInputs = with pkgs; [lief fmt nlohmann_json];
      };
    });
}
