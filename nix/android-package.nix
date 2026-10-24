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
  supports16kPages = builtins.elem arch [ "arm64-v8a" "x86_64" ];
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
naersk-lib.buildPackage {
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
    "linker=${targetCc}"
  ] ++ pkgs.lib.optionals supports16kPages [
    # NDK r27 defaults to 4 KiB. These binaries must also load on Android
    # devices with 16 KiB pages (and remain compatible with 4 KiB devices).
    "-C"
    "link-arg=-Wl,-z,max-page-size=16384"
    "-C"
    "link-arg=-Wl,-z,common-page-size=16384"
  ];

  # Check the installed binary, also used by the wheel/npm release packages.
  # Keep this in the derivation so local builds and both CI workflows enforce it.
  postInstall = pkgs.lib.optionalString supports16kPages ''
    ${targetToolchain}/bin/llvm-readelf --program-headers --wide "$out/bin/${packageName}" \
      | ${pkgs.gawk}/bin/awk '
          $1 == "LOAD" { found = 1; if (strtonum($NF) < 16384) bad = 1 }
          $1 == "GNU_RELRO" { if ((strtonum($3) + strtonum($6)) % 16384) bad = 1 }
          END { if (!found || bad) { print "ELF LOAD/RELRO segments must support 16 KiB pages"; exit 1 } }
        '
  '';

  CC = "${targetCc}";
  LD = "${targetCc}";
}
