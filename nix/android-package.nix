{ pkgs, naersk, fenixPkgs, system, version, rustSrc, android }:
arch: packageName:
let
  androidSdk = android.sdk.${system} (sdkPkgs:
    builtins.attrValues {
      inherit (sdkPkgs) ndk-27-2-12479018 cmdline-tools-latest;
    });
  androidNdkRoot = "${androidSdk}/share/android-sdk/ndk/27.2.12479018";
  androidAttrs = {
    armeabi-v7a = {
      cc = "armv7a-linux-androideabi21-clang";
      rustTarget = "armv7-linux-androideabi";
    };
    arm64-v8a = {
      cc = "aarch64-linux-android21-clang";
      rustTarget = "aarch64-linux-android";
    };
    x86 = {
      cc = "i686-linux-android21-clang";
      rustTarget = "i686-linux-android";
    };
    x86_64 = {
      cc = "x86_64-linux-android21-clang";
      rustTarget = "x86_64-linux-android";
    };
  };

  rustTarget = androidAttrs.${arch}.rustTarget;
  toolchain = fenixPkgs.combine [
    fenixPkgs.stable.rustc
    fenixPkgs.stable.cargo
    fenixPkgs.targets.${rustTarget}.stable.rust-std
  ];
  naersk-lib = pkgs.callPackage naersk {
    cargo = toolchain;
    rustc = toolchain;
  };
  targetToolchain = "${androidNdkRoot}/toolchains/llvm/prebuilt/linux-x86_64";
  targetCcName = androidAttrs.${arch}.cc;
  targetCc = "${targetToolchain}/bin/${targetCcName}";
in
naersk-lib.buildPackage rec {
  pname = packageName;
  cargoBuildOptions = x: x ++ [ "--package" packageName ];
  inherit version;
  strictDeps = true;
  src = rustSrc;
  nativeBuildInputs = [
    pkgs.perl # Needed to build vendored OpenSSL.
  ];
  auditable = false; # Avoid cargo-auditable failures.
  doCheck = false; # Disable test as it requires network access.

  CARGO_BUILD_TARGET = rustTarget;
  TARGET_CC = "${targetCc}";
  CARGO_BUILD_RUSTFLAGS = [
    "-C"
    "linker=${TARGET_CC}"
  ];

  CC = "${targetCc}";
  LD = "${targetCc}";
}
