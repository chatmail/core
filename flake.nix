{
  description = "Delta Chat core";
  inputs = {
    fenix.url = "github:nix-community/fenix";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    nix-filter.url = "github:numtide/nix-filter";
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    android.url = "github:tadfisher/android-nixpkgs";
  };
  outputs = { self, nixpkgs, flake-utils, nix-filter, naersk, fenix, android }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs.stdenv) isDarwin;
        fenixPkgs = fenix.packages.${system};
        naersk' = pkgs.callPackage naersk { };
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
            ./CONTRIBUTING.md
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

        # Map from architecture name to rust targets and nixpkgs targets.
        arch2targets = {
          "x86_64-linux" = {
            rustTarget = "x86_64-unknown-linux-musl";
            crossTarget = "x86_64-unknown-linux-musl";
          };
          "armv7l-linux" = {
            rustTarget = "armv7-unknown-linux-musleabihf";
            crossTarget = "armv7l-unknown-linux-musleabihf";
          };
          "armv6l-linux" = {
            rustTarget = "arm-unknown-linux-musleabihf";
            crossTarget = "armv6l-unknown-linux-musleabihf";
          };
          "aarch64-linux" = {
            rustTarget = "aarch64-unknown-linux-musl";
            crossTarget = "aarch64-unknown-linux-musl";
          };
          "i686-linux" = {
            rustTarget = "i686-unknown-linux-musl";
            crossTarget = "i686-unknown-linux-musl";
          };

          "x86_64-darwin" = {
            rustTarget = "x86_64-apple-darwin";
            crossTarget = "x86_64-darwin";
          };
          "aarch64-darwin" = {
            rustTarget = "aarch64-apple-darwin";
            crossTarget = "aarch64-darwin";
          };
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
            buildInputs = pkgs.lib.optionals isDarwin [
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
            auditable = false; # Avoid cargo-auditable failures.
            doCheck = false; # Disable test as it requires network access.
          };
        pkgsWin64 = pkgs.pkgsCross.mingwW64;
        mkWin64RustPackage = packageName:
          let
            rustTarget = "x86_64-pc-windows-gnu";
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
              pkgsWin64.windows.pthreads
            ];
            auditable = false; # Avoid cargo-auditable failures.
            doCheck = false; # Disable test as it requires network access.

            CARGO_BUILD_TARGET = rustTarget;
            TARGET_CC = "${pkgsWin64.stdenv.cc}/bin/${pkgsWin64.stdenv.cc.targetPrefix}cc";
            CARGO_BUILD_RUSTFLAGS = [
              "-C"
              "linker=${TARGET_CC}"
            ];

            CC = "${pkgsWin64.stdenv.cc}/bin/${pkgsWin64.stdenv.cc.targetPrefix}cc";
            LD = "${pkgsWin64.stdenv.cc}/bin/${pkgsWin64.stdenv.cc.targetPrefix}cc";
          };

        pkgsWin32 = pkgs.pkgsCross.mingw32;
        mkWin32RustPackage = packageName:
          let
            rustTarget = "i686-pc-windows-gnu";
          in
          let
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
                  "--disable-sjlj-exceptions --with-dwarf2"
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
              pkgsWin32.windows.pthreads
            ];
            auditable = false; # Avoid cargo-auditable failures.
            doCheck = false; # Disable test as it requires network access.

            CARGO_BUILD_TARGET = rustTarget;
            TARGET_CC = "${winCC}/bin/${winCC.targetPrefix}cc";
            CARGO_BUILD_RUSTFLAGS = [
              "-C"
              "linker=${TARGET_CC}"
            ];

            CC = "${winCC}/bin/${winCC.targetPrefix}cc";
            LD = "${winCC}/bin/${winCC.targetPrefix}cc";
          };

        mkCrossRustPackage = arch: packageName:
          let
            rustTarget = arch2targets."${arch}".rustTarget;
            crossTarget = arch2targets."${arch}".crossTarget;
            pkgsCross = import nixpkgs {
              system = system;
              crossSystem.config = crossTarget;
            };
          in
          let
            toolchain = fenixPkgs.combine [
              fenixPkgs.stable.rustc
              fenixPkgs.stable.cargo
              fenixPkgs.targets.${rustTarget}.stable.rust-std
            ];
            naersk-lib = pkgs.callPackage naersk {
              cargo = toolchain;
              rustc = toolchain;
            };
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
            TARGET_CC = "${pkgsCross.stdenv.cc}/bin/${pkgsCross.stdenv.cc.targetPrefix}cc";
            CARGO_BUILD_RUSTFLAGS = [
              "-C"
              "linker=${TARGET_CC}"
            ];

            CC = "${pkgsCross.stdenv.cc}/bin/${pkgsCross.stdenv.cc.targetPrefix}cc";
            LD = "${pkgsCross.stdenv.cc}/bin/${pkgsCross.stdenv.cc.targetPrefix}cc";
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
              pkgs.stdenv.mkDerivation {
                pname = "deltachat-rpc-server-${arch}-android-wheel";
                version = manifest.version;
                src = nix-filter.lib {
                  root = ./.;
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
                  cp ${rpc-server}/bin/deltachat-rpc-server tmp/deltachat-rpc-server
                  python3 scripts/wheel-rpc-server.py ${arch}-android tmp/deltachat-rpc-server
                '';
                installPhase = ''mkdir -p $out; cp -av deltachat_rpc_server-*.whl $out'';
              };
          };

        mkRustPackages = arch:
          let
            rpc-server = mkCrossRustPackage arch "deltachat-rpc-server";
          in
          {
            "deltachat-repl-${arch}" = mkCrossRustPackage arch "deltachat-repl";
            "deltachat-rpc-server-${arch}" = rpc-server;
            "deltachat-rpc-server-${arch}-wheel" =
              pkgs.stdenv.mkDerivation {
                pname = "deltachat-rpc-server-${arch}-wheel";
                version = manifest.version;
                src = nix-filter.lib {
                  root = ./.;
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
                  cp ${rpc-server}/bin/deltachat-rpc-server tmp/deltachat-rpc-server
                  python3 scripts/wheel-rpc-server.py ${arch} tmp/deltachat-rpc-server
                '';
                installPhase = ''mkdir -p $out; cp -av deltachat_rpc_server-*.whl $out'';
              };
          };
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
              pkgs.stdenv.mkDerivation {
                pname = "deltachat-rpc-server-win64-wheel";
                version = manifest.version;
                src = nix-filter.lib {
                  root = ./.;
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
                  deltachat-rpc-server-win64
                ];
                buildPhase = ''
                  mkdir tmp
                  cp ${deltachat-rpc-server-win64}/bin/deltachat-rpc-server.exe tmp/deltachat-rpc-server.exe
                  python3 scripts/wheel-rpc-server.py win64 tmp/deltachat-rpc-server.exe
                '';
                installPhase = ''mkdir -p $out; cp -av deltachat_rpc_server-*.whl $out'';
              };

            deltachat-repl-win32 = mkWin32RustPackage "deltachat-repl";
            deltachat-rpc-server-win32 = mkWin32RustPackage "deltachat-rpc-server";
            deltachat-rpc-server-win32-wheel =
              pkgs.stdenv.mkDerivation {
                pname = "deltachat-rpc-server-win32-wheel";
                version = manifest.version;
                src = nix-filter.lib {
                  root = ./.;
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
                  deltachat-rpc-server-win32
                ];
                buildPhase = ''
                  mkdir tmp
                  cp ${deltachat-rpc-server-win32}/bin/deltachat-rpc-server.exe tmp/deltachat-rpc-server.exe
                  python3 scripts/wheel-rpc-server.py win32 tmp/deltachat-rpc-server.exe
                '';
                installPhase = ''mkdir -p $out; cp -av deltachat_rpc_server-*.whl $out'';
              };
            # Run `nix build .#docs` to get C docs generated in `./result/`.
            docs =
              pkgs.stdenv.mkDerivation {
                pname = "docs";
                version = manifest.version;
                src = pkgs.lib.cleanSource ./.;
                nativeBuildInputs = [ pkgs.doxygen ];
                buildPhase = ''scripts/run-doxygen.sh'';
                installPhase = ''mkdir -p $out; cp -av deltachat-ffi/html deltachat-ffi/xml $out'';
              };

            libdeltachat =
              pkgs.stdenv.mkDerivation {
                pname = "libdeltachat";
                version = manifest.version;
                src = rustSrc;
                cargoDeps = pkgs.rustPlatform.importCargoLock cargoLock;

                nativeBuildInputs = [
                  pkgs.perl # Needed to build vendored OpenSSL.
                  pkgs.cmake
                  pkgs.rustPlatform.cargoSetupHook
                  pkgs.cargo
                ];
                buildInputs = pkgs.lib.optionals isDarwin [
                  pkgs.darwin.apple_sdk.frameworks.CoreFoundation
                  pkgs.darwin.apple_sdk.frameworks.Security
                  pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
                  pkgs.libiconv
                ];

                postInstall = ''
                  substituteInPlace $out/include/deltachat.h \
                    --replace __FILE__ '"${placeholder "out"}/include/deltachat.h"'
                '';
              };

            # Source package for deltachat-rpc-server.
            # Fake package that downloads Linux version,
            # needed to install deltachat-rpc-server on Android with `pip`.
            deltachat-rpc-server-source =
              pkgs.stdenv.mkDerivation {
                pname = "deltachat-rpc-server-source";
                version = manifest.version;
                src = pkgs.lib.cleanSource ./.;
                nativeBuildInputs = [
                  pkgs.python3
                  pkgs.python3Packages.wheel
                ];
                buildPhase = ''python3 scripts/wheel-rpc-server.py source deltachat_rpc_server-${manifest.version}.tar.gz'';
                installPhase = ''mkdir -p $out; cp -av deltachat_rpc_server-${manifest.version}.tar.gz $out'';
              };

            deltachat-rpc-client =
              pkgs.python3Packages.buildPythonPackage {
                pname = "deltachat-rpc-client";
                version = manifest.version;
                src = pkgs.lib.cleanSource ./deltachat-rpc-client;
                format = "pyproject";
                propagatedBuildInputs = [
                  pkgs.python3Packages.setuptools
                  pkgs.python3Packages.imap-tools
                ];
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
            python-docs =
              pkgs.stdenv.mkDerivation {
                pname = "docs";
                version = manifest.version;
                src = pkgs.lib.cleanSource ./.;
                buildInputs = [
                  deltachat-python
                  deltachat-rpc-client
                  pkgs.python3Packages.breathe
                  pkgs.python3Packages.sphinx_rtd_theme
                ];
                nativeBuildInputs = [ pkgs.sphinx ];
                buildPhase = ''sphinx-build -b html -a python/doc/ dist/html'';
                installPhase = ''mkdir -p $out; cp -av dist/html $out'';
              };
          };

        devShells.default =
          let
            pkgs = import nixpkgs {
              system = system;
              overlays = [ fenix.overlays.default ];
            };
          in
          pkgs.mkShell {

            buildInputs = with pkgs; [
              (fenix.packages.${system}.complete.withComponents [
                "cargo"
                "clippy"
                "rust-src"
                "rustc"
                "rustfmt"
              ])
              cargo-deny
              rust-analyzer-nightly
              cargo-nextest
              perl # needed to build vendored OpenSSL
              git-cliff
              (python3.withPackages (pypkgs: with pypkgs; [
                tox
              ]))
            ];
          };
      }
    );
}
