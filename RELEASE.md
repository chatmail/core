# Releasing a new version of chatmail core

For example, to release version 1.116.0 of the core, do the following steps.

1. Resolve all [blocker issues](https://github.com/chatmail/core/labels/blocker).

2. Update the changelog: `git cliff --unreleased --tag 1.116.0 --prepend CHANGELOG.md` or `git cliff -u -t 1.116.0 -p CHANGELOG.md`.

3. add a link to compare previous with current version to the end of CHANGELOG.md:
  `[1.116.0]: https://github.com/chatmail/core/compare/v1.115.2...v1.116.0`

4. Update the version by running `scripts/set_core_version.py 1.116.0`.

5. Commit the changes as `chore(release): prepare for 1.116.0`.
   Optionally, use a separate branch like `prep-1.116.0` for this commit and open a PR for review.

6. Push the commit to the `main` branch.

7. Once the commit is on the `main` branch and passed CI, tag the release: `git tag --annotate v1.116.0`.

8. Push the release tag: `git push origin v1.116.0`.

9. Create a GitHub release: `gh release create v1.116.0 --notes ''`.

## Dealing with failed releases

Once you make a GitHub release,
CI will try to build and publish [PyPI](https://pypi.org/) and [npm](https://www.npmjs.com/) packages.
If this fails for some reason, do not modify the failed tag, do not delete it and do not force-push to the `main` branch.
Fix the build process and tag a new release instead.
