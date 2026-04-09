#!/usr/bin/env python3
#
# Script to check that current version ends with -dev.
# Meant to be run in CI to check that PRs are made against the -dev version.
# If the version is not -dev, it was forgotten to be updated
# after making a release.

from pathlib import Path
import tomllib
import sys


def main():
    with Path("Cargo.toml").open("rb") as fp:
        cargo_toml = tomllib.load(fp)
    version = cargo_toml["package"]["version"]
    if not version.endswith("-dev"):
        print(f"Current version {version} does not end with -dev", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
