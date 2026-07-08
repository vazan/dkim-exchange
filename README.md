# Exchange DKIM Signer (Fork)

This repository is a maintained fork of the original project: [Pro/dkim-exchange](https://github.com/Pro/dkim-exchange).

Credit for the original implementation and project foundation goes to the original authors and contributors of `Pro/dkim-exchange`.

## What This Project Does

Exchange DKIM Signer adds DomainKeys Identified Mail (DKIM) signing support to on-premises Microsoft Exchange Server transport flow.

It contains:

- `Exchange.DkimSigner`: the Exchange routing/transport agent that signs outgoing messages.
- `Configuration.DkimSigner`: the Windows Forms configuration and install/upgrade/uninstall utility.

## Upstream Origin

- Original source: [https://github.com/Pro/dkim-exchange](https://github.com/Pro/dkim-exchange)
- This fork keeps the same core goal while carrying additional maintenance and behavior changes.

## Notable Fork Changes

Based on the current codebase, this fork includes these notable updates:

### 1. Dependency security updates
- `MimeKit` upgraded to `4.15.1`.
- `BouncyCastle.Cryptography` pinned to `2.6.2`.

### 2. Flattened mirrored build output
- Repository-level `Directory.Build.targets` mirrors each project build output into `Resources/build` after build.
- `Clean` removes the mirrored `Resources/build` directory.
- Normal per-project `bin/Debug` and `bin/Release` outputs are still preserved.

### 3. DKIM algorithm and signing behavior updates
- Supports `RsaSha1`, `RsaSha256`, and `Ed25519Sha256` in configuration.
- Includes fork-specific dual-sign behavior in the signer:
  - Looks for per-domain key files named `<domain>.rsa.pem` and `<domain>.ed25519.pem` next to the configured key path.
  - If present and valid, both signatures are applied with forced selectors:
    - RSA selector: `2026051800`
    - Ed25519 selector: `2026051801`

### 4. Runtime configuration reload
- The transport agent watches `settings.xml` and reloads settings on change.

## Differences vs Upstream (Tracking)

This table tracks fork-specific changes relative to the original upstream repository.

| Date (UTC) | Area | Fork Change | Why It Matters |
|---|---|---|---|
| 2026-07-08 | Dependency security | Upgraded `MimeKit` to `4.15.1` and pinned `BouncyCastle.Cryptography` to `2.6.2`. | Addresses known dependency vulnerabilities and keeps signing stack current. |
| 2026-07-08 | Build artifacts | Added repository-level output mirroring to `Resources/build` via `Directory.Build.targets`, with cleanup on `Clean`. | Produces a single flattened folder suitable for packaging and install workflows. |
| 2026-07-08 | DKIM behavior | Added dual-sign key discovery (`<domain>.rsa.pem` and `<domain>.ed25519.pem`) with forced selectors (`2026051800`, `2026051801`) when keys are available. | Enables concurrent RSA + Ed25519 signatures for staged adoption and DNS migration patterns. |
| 2026-07-08 | Runtime ops | Retains settings hot-reload from `settings.xml` using file watching in the transport agent factory. | Reduces operational friction by applying config updates without code redeploy. |

When introducing new fork-only behavior, add a new row with date, scope, and impact.

## Release Notes (Fork)

### Unreleased

- Maintained as a fork of `Pro/dkim-exchange` with explicit upstream attribution.
- Added upstream-difference tracking table in this README.

### 2026-07-08

- Security: upgraded `MimeKit` to `4.15.1` and pinned `BouncyCastle.Cryptography` to `2.6.2`.
- Build: mirrored project outputs to `Resources/build` through repository-level MSBuild targets.
- Signing: supports fork dual-sign behavior using `<domain>.rsa.pem` and `<domain>.ed25519.pem` when present.
- Operations: runtime reload of `settings.xml` remains active in the transport-agent factory watcher.

## Requirements

- Windows environment with Microsoft Exchange Server (on-prem) where transport agents are supported.
- .NET Framework target in this solution: `v4.8`.
- Visual Studio/MSBuild toolchain capable of building legacy .NET Framework projects.

Compatibility guidance from upstream (verify in your environment):

- Exchange Server 2019
- Exchange Server 2016 (CU13+)
- Exchange Server 2013 (CU23+)

## Build

1. Open `DkimSigner.sln` in Visual Studio.
2. Build `Debug` or `Release`.
3. Collect artifacts from either:
  - Project-local output folders under each project `bin/...`.
  - Unified mirrored output folder: `Resources/build`.

## Project Layout

- `Src/Exchange.DkimSigner`: transport agent library (`ExchangeDkimSigner.dll`).
- `Src/Configuration.DkimSigner`: installer/configuration GUI (`Configuration.DkimSigner.exe`).
- `Resources/Tests`: local test assets and example key material for development/testing.
- `Directory.Build.targets`: shared output mirroring behavior.

## Configuration Notes

- Runtime settings are stored in `settings.xml` near the deployed agent assembly.
- Domain entries, selectors, headers to sign, canonicalization, and algorithm are controlled through settings and/or the configuration utility.
- The signer always ensures `From` is part of signed headers.

## Install/Operations Notes

- The configuration utility includes install, inplace upgrade, and uninstall modes.
- Command-line entry flags: `--install`, `--upgrade-inplace`, `--uninstall`, `--debug`.

## License

This repository includes `LICENSE` (LGPL v3 with exception) and preserves upstream licensing terms.

## Attribution

If you are looking for original documentation/wiki history, start with the upstream repository:

- [https://github.com/Pro/dkim-exchange](https://github.com/Pro/dkim-exchange)