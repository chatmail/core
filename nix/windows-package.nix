{ pkgs, naersk, fenixPkgs, version, pkgsWindows }:
packageName:
let
  rustTarget = pkgsWindows.stdenv.hostPlatform.rust.rustcTarget;
  toolchainWin = fenixPkgs.combine [
    fenixPkgs.stable.rustc
    fenixPkgs.stable.cargo
    fenixPkgs.targets.${rustTarget}.stable.rust-std
  ];
  naerskWin = pkgs.callPackage naersk {
    cargo = toolchainWin;
    rustc = toolchainWin;
  };
  targetCc = "${pkgsWindows.stdenv.cc}/bin/${pkgsWindows.stdenv.cc.targetPrefix}cc";
  isArm64 = pkgsWindows.stdenv.hostPlatform.isAarch64;
  # openssl-src does not support aarch64-pc-windows-gnullvm yet.
  openssl = (pkgsWindows.openssl_3_6.override { static = true; }).overrideAttrs {
    configureScript = "./Configure mingwarm64";
  };
in
naerskWin.buildPackage ({
  pname = packageName;
  cargoBuildOptions = x: x ++ [ "--package" packageName ];
  inherit version;
  strictDeps = true;
  src = pkgs.lib.cleanSource ../.;
  nativeBuildInputs = [
    pkgs.perl # Needed to build vendored OpenSSL.
  ];
  depsBuildBuild = [
    pkgsWindows.stdenv.cc
  ];
  buildInputs = [
    pkgsWindows.windows.pthreads
  ];
  auditable = false; # Avoid cargo-auditable failures.
  doCheck = false; # Disable test as it requires network access.

  CARGO_BUILD_TARGET = rustTarget;
  TARGET_CC = "${targetCc}";
  "CFLAGS_${builtins.replaceStrings [ "-" ] [ "_" ] rustTarget}" = "-I${pkgsWindows.windows.pthreads}/include";
  CARGO_BUILD_RUSTFLAGS = [
    "-C"
    "linker=${targetCc}"
    "-L"
    "native=${pkgsWindows.windows.pthreads}/lib"
  ] ++ pkgs.lib.optionals isArm64 [
    "-C"
    "target-feature=+crt-static"
    "-C"
    "link-arg=-static"
    "-C"
    "link-arg=-Wl,--no-insert-timestamp"
  ];

  CC = "${targetCc}";
  LD = "${targetCc}";
} // pkgs.lib.optionalAttrs isArm64 {
  HOST_CC = "${pkgs.stdenv.cc}/bin/cc";
  TARGET_AR = "${pkgsWindows.stdenv.cc.bintools}/bin/${pkgsWindows.stdenv.cc.targetPrefix}ar";
  OPENSSL_NO_VENDOR = "1";
  OPENSSL_STATIC = "1";
  OPENSSL_LIB_DIR = "${pkgs.lib.getLib openssl}/lib";
  OPENSSL_INCLUDE_DIR = "${pkgs.lib.getDev openssl}/include";
})
