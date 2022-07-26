with import <nixpkgs>{};

let
    pkgs = import <nixpkgs> {};
    sources = import ./nix/sources.nix;
    naersk = pkgs.callPackage sources.naersk {};
in naersk.buildPackage {
  pname = "minimint";
  version = "ci";
  src = builtins.filterSource (p: t: lib.cleanSourceFilter p t && baseNameOf p != "target") ./.;
  buildInputs = [
      pkgs.clang
      pkgs.git
      pkgs.openssl
      pkgs.pkg-config
      pkgs.perl
  ];
  gitSubmodules = true;
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

}