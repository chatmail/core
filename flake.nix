{
  description = "Chatmail core";
  inputs = {
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk/pull/391/head";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
    naersk.inputs.fenix.follows = "fenix";
    nix-filter.url = "github:numtide/nix-filter";
    nixpkgs.url = "github:nixos/nixpkgs/master";
    android.url = "github:tadfisher/android-nixpkgs";
    android.inputs.nixpkgs.follows = "nixpkgs";
    android.inputs.flake-utils.follows = "flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils, nix-filter, naersk, fenix, android }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs.stdenv) isDarwin;
        fenixPkgs = fenix.packages.${system};
        fenixToolchain = fenixPkgs.combine [
          fenixPkgs.stable.rustc
          fenixPkgs.stable.cargo
          fenixPkgs.stable.rust-std
        ];
        naersk' = pkgs.callPackage naersk {
          cargo = fenixToolchain;
          rustc = fenixToolchain;
        };
        manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
        androidSdk = android.sdk.${system} (sdkPkgs:
          builtins.attrValues {
            inherit (sdkPkgs) ndk-27-2-12479018 cmdline-tools-latest;
          });
        androidNdkRoot = "${androidSdk}/share/android-sdk/ndk/27.2.12479018";

        rustSrc = nix-filter.lib {
          root = ./.;

          # Include only necessary files
          # to avoid rebuilds e.g. when README.md or flake.nix changes.
          include = [
            ./benches
            ./assets
            ./fuzz
            ./Cargo.lock
            ./Cargo.toml
            ./CMakeLists.txt
            ./deltachat_derive
            ./deltachat-contact-tools
            ./deltachat-ffi
            ./deltachat-jsonrpc
            ./deltachat-ratelimit
            ./deltachat-repl
            ./deltachat-rpc-client
            ./deltachat-time
            ./deltachat-rpc-server
            ./format-flowed
            ./release-date.in
            ./src
          ];
          exclude = [
            (nix-filter.lib.matchExt "nix")
            "flake.lock"
          ];
        };

        # Map from architecture name to nixpkgs targets.
        arch2targets = {
          "x86_64-linux" = "x86_64-unknown-linux-musl";
          "armv7l-linux" = "armv7l-unknown-linux-musleabihf";
          "armv6l-linux" = "armv6l-unknown-linux-musleabihf";
          "aarch64-linux" = "aarch64-unknown-linux-musl";
          "i686-linux" = "i686-unknown-linux-musl";
          "x86_64-darwin" = "x86_64-darwin";
          "aarch64-darwin" = "aarch64-darwin";
        };
        cargoLock = {
          lockFile = ./Cargo.lock;
        };
        mkRustPackage = packageName:
          naersk'.buildPackage {
            pname = packageName;
            cargoBuildOptions = x: x ++ [ "--package" packageName ];
            version = manifest.version;
            src = pkgs.lib.cleanSource ./.;
            nativeBuildInputs = [
              pkgs.perl # Needed to build vendored OpenSSL.
            ];
            auditable = false; # Avoid cargo-auditable failures.
            doCheck = false; # Disable test as it requires network access.
          };
        mkWin64RustPackage = packageName:
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
            version = manifest.version;
            strictDeps = true;
            src = pkgs.lib.cleanSource ./.;
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
            CARGO_BUILD_RUSTFLAGS = [
              "-C"
              "linker=${TARGET_CC}"
              "-L"
              "native=${pkgsWin64.windows.pthreads}/lib"
            ];

            CC = "${pkgsWin64.stdenv.cc}/bin/${pkgsWin64.stdenv.cc.targetPrefix}cc";
            LD = "${pkgsWin64.stdenv.cc}/bin/${pkgsWin64.stdenv.cc.targetPrefix}cc";
          };

        mkWin32RustPackage = packageName:
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
            version = manifest.version;
            strictDeps = true;
            src = pkgs.lib.cleanSource ./.;
            nativeBuildInputs = [
              pkgs.perl # Needed to build vendored OpenSSL.
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
            CARGO_BUILD_RUSTFLAGS = [
              "-C"
              "linker=${TARGET_CC}"
              "-L"
              "native=${pkgsWin32.windows.pthreads}/lib"
            ];

            CC = "${winCC}/bin/${winCC.targetPrefix}cc";
            LD = "${winCC}/bin/${winCC.targetPrefix}cc";
          };

        mkCrossRustPackage = pkgs.callPackage ./nix/cross-rust-package.nix {
          inherit nixpkgs arch2targets naersk fenixPkgs system rustSrc;
          version = manifest.version;
        };

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

        mkAndroidRustPackage = arch: packageName:
          let
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
            version = manifest.version;
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
          };

        mkAndroidPackages = arch:
          let
            rpc-server = mkAndroidRustPackage arch "deltachat-rpc-server";
          in
          {
            "deltachat-rpc-server-${arch}-android" = rpc-server;
            "deltachat-repl-${arch}-android" = mkAndroidRustPackage arch "deltachat-repl";
            "deltachat-rpc-server-${arch}-android-wheel" =
              mkWheel { inherit rpc-server; arch = "${arch}-android"; };
          };

        mkRustPackages = arch:
          let
            rpc-server = mkCrossRustPackage arch "deltachat-rpc-server";
          in
          {
            "deltachat-repl-${arch}" = mkCrossRustPackage arch "deltachat-repl";
            "deltachat-rpc-server-${arch}" = rpc-server;
            "deltachat-rpc-server-${arch}-wheel" = mkWheel { inherit rpc-server; arch = "${arch}"; };
          };

        mkWheel = pkgs.callPackage ./nix/wheel.nix { inherit nix-filter; version = manifest.version; root = ./.; };
      in
      {
        formatter = pkgs.nixpkgs-fmt;

        packages =
          mkRustPackages "aarch64-linux" //
          mkRustPackages "i686-linux" //
          mkRustPackages "x86_64-linux" //
          mkRustPackages "armv7l-linux" //
          mkRustPackages "armv6l-linux" //
          mkRustPackages "x86_64-darwin" //
          mkRustPackages "aarch64-darwin" //
          mkAndroidPackages "armeabi-v7a" //
          mkAndroidPackages "arm64-v8a" //
          mkAndroidPackages "x86" //
          mkAndroidPackages "x86_64" // rec {
            # Run with `nix run .#deltachat-repl foo.db`.
            deltachat-repl = mkRustPackage "deltachat-repl";
            deltachat-rpc-server = mkRustPackage "deltachat-rpc-server";

            deltachat-repl-win64 = mkWin64RustPackage "deltachat-repl";
            deltachat-rpc-server-win64 = mkWin64RustPackage "deltachat-rpc-server";
            deltachat-rpc-server-win64-wheel =
              mkWheel { rpc-server = deltachat-rpc-server-win64; arch = "win64"; binaryName = "deltachat-rpc-server.exe"; };

            deltachat-repl-win32 = mkWin32RustPackage "deltachat-repl";
            deltachat-rpc-server-win32 = mkWin32RustPackage "deltachat-rpc-server";
            deltachat-rpc-server-win32-wheel =
              mkWheel
                { rpc-server = deltachat-rpc-server-win32; arch = "win32"; binaryName = "deltachat-rpc-server.exe"; };

            # Run `nix build .#docs` to get C docs generated in `./result/`.
            docs = pkgs.callPackage ./nix/c-docs.nix { version = manifest.version; };

            libdeltachat = pkgs.callPackage ./nix/libdeltachat.nix {
              inherit fenixToolchain rustSrc cargoLock fenixPkgs;
              version = manifest.version;
            };

            deltachat-rpc-client = pkgs.callPackage ./nix/deltachat-rpc-client.nix {
              version = manifest.version;
            };

            deltachat-python =
              pkgs.python3Packages.buildPythonPackage {
                pname = "deltachat-python";
                version = manifest.version;
                src = pkgs.lib.cleanSource ./python;
                format = "pyproject";
                buildInputs = [
                  libdeltachat
                ];
                nativeBuildInputs = [
                  pkgs.pkg-config
                ];
                propagatedBuildInputs = [
                  pkgs.python3Packages.setuptools
                  pkgs.python3Packages.pkgconfig
                  pkgs.python3Packages.cffi
                  pkgs.python3Packages.imap-tools
                  pkgs.python3Packages.pluggy
                  pkgs.python3Packages.requests
                ];
              };
            python-docs = pkgs.callPackage ./nix/python-docs.nix {
              inherit deltachat-python deltachat-rpc-client;
              version = manifest.version;
            };
          };

        devShells.default = import ./nix/devshell.nix { inherit nixpkgs fenix system; };
      }
    );
}
