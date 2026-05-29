{ pkgs, version }:
pkgs.python3Packages.buildPythonPackage {
  pname = "deltachat-rpc-client";
  inherit version;
  src = pkgs.lib.cleanSource ../deltachat-rpc-client;
  format = "pyproject";
  propagatedBuildInputs = [
    pkgs.python3Packages.setuptools
    pkgs.python3Packages.imap-tools
  ];
}
