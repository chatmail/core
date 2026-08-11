{ pkgs, version }:
pkgs.stdenv.mkDerivation {
  pname = "docs";
  inherit version;
  src = pkgs.lib.cleanSource ../.;
  nativeBuildInputs = [ pkgs.doxygen ];
  buildPhase = ''scripts/run-doxygen.sh'';
  installPhase = ''mkdir -p $out; cp -av deltachat-ffi/html deltachat-ffi/xml $out'';
}
