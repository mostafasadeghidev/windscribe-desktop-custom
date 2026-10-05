# Private desktop fork workflow

This repository is private and keeps the Windscribe upstream history. The local `upstream` remote points to `Windscribe/Desktop-App`; `origin` points to this private repository.

## Bring in upstream changes

In GitHub, open **Actions → Prepare upstream update pull request → Run workflow**. It fetches upstream `master`, merges it into a review branch, and opens a pull request. Review conflicts and the diff, merge the PR only after review, then run the needed build workflow.

If the sync workflow reports conflicts, resolve them locally in a branch and open a pull request. Git does not automatically separate upstream protocol code from modifications that touch the same lines.

## Build private test packages

Open **Actions** and manually run the workflow for Windows, macOS, or Linux. Download the resulting artifact from that run. Workflows use developer/test mode and are not for public release. Artifacts expire after 14 days. macOS system extensions and IKEv2 still have Apple entitlement/signing restrictions.

Builds run only when manually requested because these desktop builds are large and private GitHub Actions minutes are limited.
