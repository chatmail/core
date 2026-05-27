{ pkgs, nixpkgs, arch2targets, naersk, fenixPkgs, system, rustSrc, version }:
arch: packageName:
let
  crossTarget = arch2targets."${arch}";
  pkgsCross =
    if crossTarget == system then
      import nixpkgs { inherit system; }
    else
      import nixpkgs {
        system = system;
        crossSystem.config = crossTarget;
      };
  rustTarget = pkgsCross.stdenv.hostPlatform.rust.rustcTarget;
  toolchain = fenixPkgs.combine [
    fenixPkgs.stable.rustc
    fenixPkgs.stable.cargo
    fenixPkgs.targets.${rustTarget}.stable.rust-std
  ];
  naersk-lib = (pkgs.callPackage naersk {
    cargo = toolchain;
    rustc = toolchain;
  }).override {
    pkgs = pkgsCross;
  };
in
naersk-lib.buildPackage rec {
  pname = packageName;
  cargoBuildOptions = x: x ++ [ "--package" packageName ];
  inherit version;
  strictDeps = true;
  src = rustSrc;
  nativeBuildInputs = [
    pkgsCross.buildPackages.perl # Needed to build vendored OpenSSL.
  ];
  auditable = false; # Avoid cargo-auditable failures.
  doCheck = false; # Disable test as it requires network access.

  CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTFLAGS = "-Clink-args=-L${pkgsCross.libiconv}/lib";
  CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS = "-Clink-args=-L${pkgsCross.libiconv}/lib";

  CARGO_BUILD_TARGET = rustTarget;
  TARGET_CC = "${pkgsCross.stdenv.cc}/bin/${pkgsCross.stdenv.cc.targetPrefix}cc";
  CARGO_BUILD_RUSTFLAGS = [
    "-C"
    "linker=${TARGET_CC}"
  ];

  CC = "${pkgsCross.stdenv.cc}/bin/${pkgsCross.stdenv.cc.targetPrefix}cc";
  LD = "${pkgsCross.stdenv.cc}/bin/${pkgsCross.stdenv.cc.targetPrefix}cc";
}
