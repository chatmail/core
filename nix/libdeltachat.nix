{ pkgs, fenixToolchain, rustSrc, cargoLock, fenixPkgs, version }:
let
  rustPlatform = (pkgs.makeRustPlatform {
    cargo = fenixToolchain;
    rustc = fenixToolchain;
  });
in
pkgs.stdenv.mkDerivation {
  pname = "libdeltachat";
  inherit version;
  src = rustSrc;
  cargoDeps = pkgs.rustPlatform.importCargoLock cargoLock;

  nativeBuildInputs = [
    pkgs.perl # Needed to build vendored OpenSSL.
    pkgs.cmake
    rustPlatform.cargoSetupHook
    fenixPkgs.stable.rustc
    fenixPkgs.stable.cargo
  ];

  postInstall = ''
    substituteInPlace $out/include/deltachat.h \
      --replace __FILE__ '"${placeholder "out"}/include/deltachat.h"'
  '';
}
