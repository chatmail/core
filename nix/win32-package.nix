{ pkgs, naersk, fenixPkgs, system, version }:
packageName:
let
  pkgsWin32 = pkgs.pkgsCross.mingw32;
  rustTarget = pkgsWin32.stdenv.hostPlatform.rust.rustcTarget;
  toolchainWin = fenixPkgs.combine [
    fenixPkgs.stable.rustc
    fenixPkgs.stable.cargo
    fenixPkgs.targets.${rustTarget}.stable.rust-std
  ];
  naerskWin = pkgs.callPackage naersk {
    cargo = toolchainWin;
    rustc = toolchainWin;
  };

  # Get rid of MCF Gthread library.
  # See <https://github.com/NixOS/nixpkgs/issues/156343>
  # and <https://discourse.nixos.org/t/statically-linked-mingw-binaries/38395>
  # for details.
  #
  # Use DWARF-2 instead of SJLJ for exception handling.
  winCC = pkgsWin32.buildPackages.wrapCC (
    (pkgsWin32.buildPackages.gcc-unwrapped.override
      ({
        threadsCross = {
          model = "win32";
          package = null;
        };
      })).overrideAttrs (oldAttr: {
      configureFlags = oldAttr.configureFlags ++ [
        "--disable-sjlj-exceptions"
        "--with-dwarf2"
      ];
    })
  );
in
naerskWin.buildPackage rec {
  pname = packageName;
  cargoBuildOptions = x: x ++ [ "--package" packageName ];
  inherit version;
  strictDeps = true;
  src = pkgs.lib.cleanSource ../.;
  nativeBuildInputs = [
    pkgs.perl # Needed to build vendored OpenSSL.
    pkgs.nasm # aws-lc-sys requires it
  ];
  depsBuildBuild = [
    winCC
  ];
  buildInputs = [
    pkgsWin32.windows.pthreads
  ];
  auditable = false; # Avoid cargo-auditable failures.
  doCheck = false; # Disable test as it requires network access.

  CARGO_BUILD_TARGET = rustTarget;
  TARGET_CC = "${winCC}/bin/${winCC.targetPrefix}cc";
  CFLAGS_i686_pc_windows_gnu = "-I${pkgsWin32.windows.pthreads}/include";
  CARGO_BUILD_RUSTFLAGS = [
    "-C"
    "linker=${TARGET_CC}"
    "-L"
    "native=${pkgsWin32.windows.pthreads}/lib"
  ];

  CC = "${winCC}/bin/${winCC.targetPrefix}cc";
  LD = "${winCC}/bin/${winCC.targetPrefix}cc";
}
