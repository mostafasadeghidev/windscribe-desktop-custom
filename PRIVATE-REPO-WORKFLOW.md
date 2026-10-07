# Private desktop fork workflow

This repository is private and keeps the Windscribe upstream history. The local `upstream` remote points to `Windscribe/Desktop-App`; `origin` points to this private repository.

## Bring in upstream changes

In GitHub, open **Actions → Prepare upstream update pull request → Run workflow**. It fetches upstream `master`, merges it into a review branch, and opens a pull request. Review conflicts and the diff, merge the PR only after review, then run the needed build workflow.

If the sync workflow reports conflicts, resolve them locally in a branch and open a pull request. Git does not automatically separate upstream protocol code from modifications that touch the same lines.

## Build private test packages

Open **Actions** and manually run the workflow for Windows, macOS, or Linux. Download the resulting artifact from that run. Workflows use developer/test mode and are not for public release. Windows installers and macOS app/disk images use the private test code-signing identity; Linux Debian packages include a detached signature and the public certificate. Artifacts expire after 14 days.

The signing identity is self-signed for private testing. It does not provide Microsoft Smart App Control reputation or Apple Developer ID notarization, and macOS system extensions/IKEv2 still have Apple entitlement restrictions. Keep the PFX and password in repository Actions secrets only; never commit them.

Builds run only when manually requested because these desktop builds are large and private GitHub Actions minutes are limited.

Each successful build also attaches its signed package to a GitHub pre-release tagged `v<version>-private-<short commit>`. All three platforms share the release for the same commit, so running the Windows, macOS, and Linux workflows on the same commit yields one release with every installer. Releases do not expire; use the **Releases** page for downloads that must outlive the 14-day artifact window.

## Install updates

Private test builds skip Windscribe's updater and hide the vendor update-channel selector. Get a replacement package from this repository's **Actions** artifacts and install it manually. Verify a Linux signature with:

```sh
openssl x509 -in package.deb.cert.pem -pubkey -noout > public-key.pem
openssl dgst -sha256 -verify public-key.pem -signature package.deb.sig package.deb
```

A private GitHub repository cannot provide an in-app updater to an installed client without a separate authenticated update service; never embed a GitHub token in the app.
