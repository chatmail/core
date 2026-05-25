{ nixpkgs, fenix, system }:
let
  pkgs = import nixpkgs {
    inherit system;
    overlays = [ fenix.overlays.default ];
  };
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    (fenix.packages.${system}.complete.withComponents [
      "cargo"
      "clippy"
      "rust-src"
      "rustc"
      "rustfmt"
    ])
    cargo-deny
    rust-analyzer-nightly
    cargo-nextest
    perl # needed to build vendored OpenSSL
    git-cliff
    (python3.withPackages (pypkgs: [
      pypkgs.tox
    ]))
    nodejs
  ];
}
