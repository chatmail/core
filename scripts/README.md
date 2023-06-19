# Continuous Integration Scripts for Delta Chat

Continuous Integration, run through [GitHub
Actions](https://docs.github.com/actions)
and an own build machine.

## Description of scripts 

- `clippy.sh` runs `cargo clippy` for all Rust code in the project.

- `deny.sh` runs `cargo deny` for all Rust code in the project.

- `../.github/workflows` contains jobs run by GitHub Actions.

- `remote_tests_python.sh` rsyncs to a build machine and runs
  `run-python-test.sh` remotely on the build machine. 

- `remote_tests_rust.sh` rsyncs to the build machine and runs
  `run-rust-test.sh` remotely on the build machine. 

- `make-python-testenv.sh` creates or updates local python test development environment.
  Reusing the same environment is faster than running `run-python-test.sh` which always
  recreates environment from scratch and runs additional lints.

- `run-doxygen.sh` generates C-docs which are then uploaded to https://c.delta.chat/

- `run_all.sh` builds Python wheels

- `zig-rpc-server.sh` compiles binaries of `deltachat-rpc-server` using Zig toolchain statically linked against musl libc.

- `android-rpc-server.sh` compiles binaries of `deltachat-rpc-server` using Android NDK.

## Triggering runs on the build machine locally (fast!)

There is experimental support for triggering a remote Python or Rust test run 
from your local checkout/branch. You will need to be authorized to login to 
the build machine (ask your friendly sysadmin on #deltachat Libera Chat) to type:

    scripts/manual_remote_tests.sh rust
    scripts/manual_remote_tests.sh python

This will **rsync** your current checkout to the remote build machine 
(no need to commit before) and then run either rust or python tests. 

# coredeps Dockerfile

`coredeps/Dockerfile` specifies an image that contains all 
of Delta Chat's core dependencies. It is used to
build python wheels (binary packages for Python).

You can build the docker images yourself locally
to avoid the relatively large download:
 
    cd scripts  # where all CI things are 
    docker build -t deltachat/coredeps coredeps

Additionally, you can install qemu and build arm64 docker image on x86\_64 machine:
    apt-get install qemu binfmt-support qemu-user-static
    docker build -t deltachat/coredeps-arm64 --build-arg BASEIMAGE=quay.io/pypa/manylinux2014_aarch64 coredeps
