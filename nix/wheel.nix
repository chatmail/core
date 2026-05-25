{ pkgs, nix-filter, version, root }:
{ rpc-server, arch, binaryName ? "deltachat-rpc-server" }:
pkgs.stdenv.mkDerivation {
  pname = "deltachat-rpc-server-${arch}-wheel";
  inherit version;
  src = nix-filter.lib {
    inherit root;
    include = [
      "scripts/wheel-rpc-server.py"
      "deltachat-rpc-server/README.md"
      "LICENSE"
      "Cargo.toml"
    ];
  };
  nativeBuildInputs = [
    pkgs.python3
    pkgs.python3Packages.wheel
  ];
  buildInputs = [
    rpc-server
  ];
  buildPhase = ''
    mkdir tmp
    cp ${rpc-server}/bin/${binaryName} tmp/${binaryName}
    python3 scripts/wheel-rpc-server.py ${arch} tmp/${binaryName}
  '';
  installPhase = ''mkdir -p $out; cp -av deltachat_rpc_server-*.whl $out'';
}
