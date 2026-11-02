# Installer Analyzer for ImmyBot v0.12.10

Windows installer analysis and unattended deployment validation for ImmyBot.

## v0.12.10 assistant, Sandbox controls and performance

Adds Claude as a read-only AI provider, a Sandbox elapsed timer, clearer separate/integrated viewer layouts, improved native application logos, updated navigation icons and theme controls, and UI/performance fixes. See [v0.12.10 release notes](docs/releases/v0.12.10.md) for scope and verification limits.
## v0.12.9 lifecycle proof and custom color picker

The engine now separates the first install from the clean reinstall, verifies removal before reinstalling, and applies the same complete-proof rules to Test Mode, history, confidence and catalog admission. Initial uninstall monitoring, MSI logs, identity matching and atomic result publication improve failure diagnosis. Custom theme and accent dialogs now use a color area, vertical hue bar and editable hex value, without opacity. See [v0.12.9 release notes](docs/releases/v0.12.9.md) and the accompanying test report for observed results and remaining checks.

## v0.12.8 optional read-only AI Assist

Settings → Test Mode → Enable read-only AI Assist opens an optional diagnostic chat. It is off by default, hidden until Test Mode is enabled, and supports OpenAI or an existing local Ollama server. Configure your model and connection, then choose a test and Preview diagnostics or Explain. See [v0.12.8 release notes](docs/releases/v0.12.8.md) for setup, privacy, read-only scope and verification limits.

## v0.12.7 catalog and discovery reliability

See [release notes](docs/releases/v0.12.7.md) for the local validated catalog, RGB theme/accent controls, stop-button colors, and discovery corrections. This build was tested against the supplied USB installers; see the accompanying test report for passes and unresolved package failures.

## v0.12.6 generalized discovery

- Process-aware installer UI detection
- Second-generation extracted-payload strategy discovery
- Multi-candidate silent uninstall discovery
- Stronger Sandbox startup recovery
- Minimized Windows Sandbox during Silent Only Test Mode


## v0.12.6 Strategy Discovery Engine

Silent Only can now generate and validate ranked silent-install hypotheses for previously unseen installers instead of immediately failing when static analysis has no known strategy. Candidate outcomes are retained for diagnostics, and MSI probes emit verbose logs for failure analysis.

## v0.12.6 stabilization

- Removes optional Sandbox cleanup from the blocking analysis thread after v0.11.44 isolated the final hang to that path.
- Marks the Sandbox lifecycle complete immediately after the authoritative result and completion flag are committed; host-side teardown remains responsible for closing the Sandbox.
- Adds static Adobe Acrobat/Reader bootstrapper recognition so Adobe Download Manager launcher metadata is no longer presented as the deployed product identity.
- Keeps Adobe silent arguments validation-only until Sandbox proves the working vendor strategy.
- Renames the Analyze-page evidence label to **Installer evidence**.

## v0.11.44 finalization + heartbeat reliability

The validated lifecycle result is now committed before optional final cleanup, so Sandbox-side cleanup can no longer strand the completion handoff. Heartbeat events append to a history instead of overwriting the file. The v0.11.43 session preflight and host recovery remain intact.

## v0.11.44 host completion and timeline stability

- Host-confirmed lifecycle success now completes the session immediately instead of waiting on Sandbox-side finalization.
- Integrated Viewer state no longer overwrites analysis status.
- Current Stage uses a persistent full lifecycle timeline driven by checkpoint facts.

## v0.11.40 deterministic lifecycle state machine

Candidate execution is now separated from evaluation, cleanup, detection, and progression. A candidate that displays UI, returns a non-success exit code, or fails detection is recorded as a validation result and the analyzer advances when the Sandbox baseline is safe. This prevents an unsupported bootstrapper from turning a completed analysis into a host timeout.

## v0.11.40 Adobe post-return diagnostics

This build focuses on the v0.11.35 boundary where the staged Adobe setup candidate returned exit code 2 but lifecycle processing stopped afterward. Post-return serialization, UI-state copying, detection, rejection recording, and candidate advancement now emit granular checkpoints and heartbeat activity. Non-zero candidate exits are recorded immediately rather than entering the full detection polling window.

Adobe validation staging now copies the complete cached Acrobat Setup ProductCode directory rather than setup.exe alone, preserving adjacent vendor payload/context. The original Reader bootstrapper remains the deployment source unless a durable strategy is validated.

### v0.11.44
Adds host-side stale Windows Sandbox session cleanup before launch to recover from the "too many sessions established" startup failure while retaining the v0.11.42 completion and timeline fixes.
