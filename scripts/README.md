# Continuous Integration Scripts for Delta Chat

Continuous Integration, run through [GitHub
Actions](https://docs.github.com/actions)
and an own build machine.

## Description of scripts 

- `clippy.sh` runs `cargo clippy` for all Rust code in the project.

- `deny.sh` runs `cargo deny` for all Rust code in the project.

- `codespell.sh` spellchecks the source code using `codespell` tool.

- `../.github/workflows` contains jobs run by GitHub Actions.

- `run-python-test.sh` runs CFFI Python tests.

- `run-rpc-test.sh` runs JSON-RPC Python tests.

- `make-python-testenv.sh` creates a local python test development environment with CFFI bindings.
  Reusing the same environment is faster than running `run-python-test.sh` which always
  recreates environment from scratch and runs additional lints.

- `make-rpc-testenv.sh` creates a local python development environment with JSON-RPC bindings,
   i.e. `deltachat-rpc-client` and `deltachat-rpc-server`.

- `remote_tests_python.sh` rsyncs to a build machine and runs
  JSON-RPC Python tests remotely on the build machine. 

- `remote_tests_rust.sh` rsyncs to the build machine and runs
  Rust tests remotely on the build machine. 

- `run-doxygen.sh` generates C-docs which are then uploaded to https://c.delta.chat/

- `run_all.sh` builds Python wheels

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
