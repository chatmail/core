{
  description = "Chatmail core";
  inputs = {
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
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
        version = manifest.version;

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
          "powerpc64le-linux" = "powerpc64le-unknown-linux-musl";
          "riscv64-linux" = "riscv64-unknown-linux-musl";
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
            inherit version;
            src = pkgs.lib.cleanSource ./.;
            nativeBuildInputs = [
              pkgs.perl # Needed to build vendored OpenSSL.
            ];
            auditable = false; # Avoid cargo-auditable failures.
            doCheck = false; # Disable test as it requires network access.
          };

        mkWin64RustPackage = pkgs.callPackage ./nix/win64-package.nix {
          inherit naersk system fenixPkgs version;
        };

        mkWin32RustPackage = pkgs.callPackage ./nix/win32-package.nix {
          inherit naersk system fenixPkgs version;
        };

        mkCrossRustPackage = pkgs.callPackage ./nix/cross-rust-package.nix {
          inherit nixpkgs arch2targets naersk fenixPkgs system rustSrc version;
        };

        mkAndroidRustPackage = pkgs.callPackage ./nix/android-package.nix {
          inherit naersk fenixPkgs system rustSrc android version;
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

        mkWheel = pkgs.callPackage ./nix/wheel.nix { inherit nix-filter version; root = ./.; };
      in
      {
        formatter = pkgs.nixpkgs-fmt;

        packages =
          mkRustPackages "aarch64-linux" //
          mkRustPackages "i686-linux" //
          mkRustPackages "x86_64-linux" //
          mkRustPackages "armv7l-linux" //
          mkRustPackages "armv6l-linux" //
          mkRustPackages "powerpc64le-linux" //
          mkRustPackages "riscv64-linux" //
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
            docs = pkgs.callPackage ./nix/c-docs.nix { inherit version; };

            libdeltachat = pkgs.callPackage ./nix/libdeltachat.nix {
              inherit fenixToolchain rustSrc cargoLock fenixPkgs version;
            };

            deltachat-rpc-client = pkgs.callPackage ./nix/deltachat-rpc-client.nix {
              inherit version;
            };

            deltachat-python =
              pkgs.python3Packages.buildPythonPackage {
                pname = "deltachat-python";
                inherit version;
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
              inherit deltachat-python deltachat-rpc-client version;
            };
          };

        devShells.default = import ./nix/shell.nix { inherit nixpkgs fenix system; };
      }
    );
}
