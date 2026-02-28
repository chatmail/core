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

10. Update the version to the next development version:
    `scripts/set_core_version.py 1.117.0-dev`.

11. Commit and push the change:
    `git commit -m "chore: bump version to 1.117.0-dev" && git push origin main`.

12. Once the binaries are generated and [published](https://github.com/chatmail/core/releases),
    check Windows binaries for false positive detections at [VirusTotal].
    Either upload the binaries directly or submit a direct link to the artifact.
    You can use [old browsers interface](https://www.virustotal.com/old-browsers/)
    if there are problems with using the default website.
    If you submit a direct link and get to the page saying
    "No security vendors flagged this URL as malicious",
    it does not mean that the file itself is not detected.
    You need to go to the "details" tab
    and click on the SHA-256 hash in the "Body SHA-256" section.
    If any false positive is detected,
    open an issue to track removing it.
    See <https://github.com/chatmail/core/issues/7847>
    for an example of false positive detection issue.
    If there is a false positive "Microsoft" detection,
    mark the issue as a blocker.

[VirusTotal]: https://www.virustotal.com/

## Dealing with antivirus false positives

If Windows release is incorrectly detected by some antivirus, submit requests to remove detection.

"Microsoft" antivirus is built in Windows and will break user setups so removing its detection should be highest priority.
To submit false positive to Microsoft, go to <https://www.microsoft.com/en-us/wdsi/filesubmission> and select "Submit file as a ... Software developer" option.

False positive contacts for other vendors can be found at <https://docs.virustotal.com/docs/false-positive-contacts>.
Not all of them may be up to date, so check the links below first.
Previously we successfully used the following contacts:
- [ESET-NOD32](mailto:samples@eset.com)
- [Symantec](https://symsubmit.symantec.com/)

## Dealing with failed releases

Once you make a GitHub release,
CI will try to build and publish [PyPI](https://pypi.org/) and [npm](https://www.npmjs.com/) packages.
If this fails for some reason, do not modify the failed tag, do not delete it and do not force-push to the `main` branch.
Fix the build process and tag a new release instead.
