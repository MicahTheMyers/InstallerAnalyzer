# Open-source Windows signing options and readiness

Checked 2026-10-28. This is research and preparation, not a submitted application, license change, purchase or provider approval.

## Recommendation

Prepare Installer Analyzer for **SignPath Foundation** while continuing local development on the configured test machine. SignPath's published terms are the clearest match for free Authenticode signing through a verifiable release pipeline, but project maturity/reputation and their review still determine acceptance. Adopting an open-source license alone does not produce a certificate or guarantee acceptance.

## Options checked

| Option | Cost / availability | Fit for this project now |
|---|---|---|
| [SignPath Foundation](https://signpath.org/terms.html) | Free for accepted qualifying open-source projects; application review required. | Best preparation target. Requires an OSI-approved license, maintained/released/documented software, verifiable builds, signing-role/security practices and a published signing/privacy policy. The Foundation is the signing publisher. Reputation is reviewed; a new repository is not guaranteed approval. |
| [OSSign](https://ossign.org/) | Advertises free qualifying OSS signing, but applications are currently suspended. | Not immediately available. Published criteria also require at least six months of account/organization/project activity, a community/user base and public verifiable automation. |
| [Necessary Code Signing](https://sign.necessary.nu/) | Advertises free Windows signing under Necessary Innovations AB's shared certificate; manual approval and identity/address verification. | Its stated focus is established, widely used software with proven maintainer history. That makes it a poor immediate fit for a newly created project; eligibility has not been independently approved. No identity documents were requested or uploaded. |
| [Certum open-source cloud signing](https://shop.certum.eu/open-source-code-signing-on-simplysign.html) | Paid: shop lists from EUR49 and currently says out of stock. | An OSS discount, not a free option. The provider's general pages show different starting prices for other products; confirm an actual available product/quote before spending money. |

Provider statements about trust or reputation are not independently verified promises that every signed application will run without a Windows warning. Code-signing tools and GitHub provenance/attestations do not themselves provide a publicly trusted Authenticode signing identity.

Microsoft also offers free Store signing for certified **MSIX** submissions, but does not re-sign an ordinary MSI/EXE installer submitted through the Store's Win32 path. That is a separate packaging/distribution choice and does not sign local test builds. [Microsoft's options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)

## Repository observations

Read through the connected GitHub tools on 2026-10-28:

- Repository: [MicahTheMyers/InstallerAnalyzer](https://github.com/MicahTheMyers/InstallerAnalyzer), public, default branch `main`.
- Created 2026-10-24 UTC; GitHub currently reports no detected license and the root directory contains no LICENSE file. This is an observed readiness gap, not a choice of license on the owner's behalf.
- Published releases exist; the latest returned release is v0.11.45 with portable and setup executables and GitHub SHA-256 asset digests.
- [release.yml](https://github.com/MicahTheMyers/InstallerAnalyzer/blob/main/.github/workflows/release.yml) builds on a GitHub-hosted Windows runner, publishes a single-file portable app, builds an Inno Setup installer and uploads release assets.
- That workflow contains no signing step or verification-test job. The more recent local 0.12.9 roadmap/security changes and test harness must be integrated into a reviewed repository release process before claiming the workflow builds the current tested source.
- No repository license, workflow, release or visibility was modified during this research.

## Concrete preparation checklist

1. Have the copyright owner choose an appropriate OSI-approved license and confirm rights to license the original code/assets. Keep third-party license notices. Do not infer that a public repository already grants open-source rights. GitHub's [license chooser](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-license-to-a-repository) can add the selected text.
2. Integrate the tested local source and security fixes into the public repository, including repeatable build/fixture/dependency-audit steps. Keep installers and credentials outside the source tree.
3. Review release-workflow trust: immutable reviewed source references, least-privilege permissions, dependency/action pinning, tests before release, and protected release/signing approval. Do not add a signing token before a provider accepts the project.
4. Prepare a truthful signing policy, maintainer/reviewer/approver roles, 2FA practices and privacy description. The app's default GitHub update checks and opt-in AI requests need to be described accurately. Do not claim SignPath provides signing before acceptance.
5. Align signed product/version metadata across application and setup artifacts with the approved provider policy. Currently the app's default product label and Inno Setup product label differ; the updater expects the setup label `Installer Analyzer for ImmyBot`.
6. Design signing into the build order: own DLLs before single-file bundling, portable EXE after bundling, Inno uninstaller during setup construction, and final setup EXE afterward. Provider policy must also cover upstream native dependencies; do not sign third-party code under a Foundation project identity without approval.
7. Resolve certificate lifecycle handling before enabling automatic updates. The current updater deliberately pins the exact running-app certificate, so a new/rotated certificate requires a separately trusted transition. Free services that share a certificate across projects also require our signed product/version checks; signer identity alone is insufficient.
8. Apply through the provider's official process once the project meets its criteria, then verify the actual certificate chain, timestamps and signed release on Windows with Smart App Control enabled. Signing acceptance and real UAC/update handoff remain untested.

None of these readiness steps requires buying a certificate merely to continue current local development. Free production signing is conditional on provider acceptance and ongoing compliance.

## Isolated verification completed 2026-10-29

With explicit user permission, synthetic test certificates were trusted only inside a fresh disposable Sandbox. The production Authenticode/publisher pin, digest/product/version validation, staged-file lock/recheck and single inert setup launch passed. A valid different-certificate setup was rejected; a real untrusted signature had also been rejected. Sandbox teardown was confirmed and host trust stores were untouched. This validates the signature/launch mechanics with stubbed transport, not provider acceptance, a publicly trusted release, an actual Inno Setup upgrade/UAC flow or customer Smart App Control behavior. The development candidate remains unsigned.
