{ pkgs, naersk, fenixPkgs, system, version }:
packageName:
let
  pkgsWin64 = pkgs.pkgsCross.mingwW64;
  rustTarget = pkgsWin64.stdenv.hostPlatform.rust.rustcTarget;
  toolchainWin = fenixPkgs.combine [
    fenixPkgs.stable.rustc
    fenixPkgs.stable.cargo
    fenixPkgs.targets.${rustTarget}.stable.rust-std
  ];
  naerskWin = pkgs.callPackage naersk {
    cargo = toolchainWin;
    rustc = toolchainWin;
  };
in
naerskWin.buildPackage rec {
  pname = packageName;
  cargoBuildOptions = x: x ++ [ "--package" packageName ];
  inherit version;
  strictDeps = true;
  src = pkgs.lib.cleanSource ../.;
  nativeBuildInputs = [
    pkgs.perl # Needed to build vendored OpenSSL.
  ];
  depsBuildBuild = [
    pkgsWin64.stdenv.cc
  ];
  buildInputs = [
    pkgsWin64.windows.pthreads
  ];
  auditable = false; # Avoid cargo-auditable failures.
  doCheck = false; # Disable test as it requires network access.

  CARGO_BUILD_TARGET = rustTarget;
  TARGET_CC = "${pkgsWin64.stdenv.cc}/bin/${pkgsWin64.stdenv.cc.targetPrefix}cc";
  CFLAGS_x86_64_pc_windows_gnu = "-I${pkgsWin64.windows.pthreads}/include";
  CARGO_BUILD_RUSTFLAGS = [
    "-C"
    "linker=${TARGET_CC}"
    "-L"
    "native=${pkgsWin64.windows.pthreads}/lib"
  ];

  CC = "${pkgsWin64.stdenv.cc}/bin/${pkgsWin64.stdenv.cc.targetPrefix}cc";
  LD = "${pkgsWin64.stdenv.cc}/bin/${pkgsWin64.stdenv.cc.targetPrefix}cc";
}
