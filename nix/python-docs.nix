{ pkgs, version, deltachat-python, deltachat-rpc-client }:
pkgs.stdenv.mkDerivation {
  pname = "docs";
  inherit version;
  src = pkgs.lib.cleanSource ../.;
  buildInputs = [
    deltachat-python
    deltachat-rpc-client
    pkgs.python3Packages.breathe
    pkgs.python3Packages.sphinx-rtd-theme
  ];
  nativeBuildInputs = [ pkgs.sphinx ];
  buildPhase = ''sphinx-build -b html -a python/doc/ dist/html'';
  installPhase = ''mkdir -p $out; cp -av dist/html $out'';
}
