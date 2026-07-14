# DEV CHANGE REPORT

## Scope
Generate a single flattened build output under Resources/build whenever the solution is compiled, while preserving the existing project-local bin output layout used by the projects themselves.

## Classification
STANDARD

## Files Changed
- Directory.Build.targets

## What Changed
1. Added a repository-level `Directory.Build.targets` file so both legacy `.csproj` projects automatically participate without changing their individual `OutputPath` settings.
2. Flattened the mirror target so every file from each project's `$(TargetDir)` is copied directly into `Resources/build` instead of a nested `Src/<ProjectName>/bin/<Configuration>` tree.
3. Kept the shared-folder behavior so `Configuration.DkimSigner` and `Exchange.DkimSigner` outputs end up side by side in the same build folder.
4. Kept a matching `AfterTargets="Clean"` target that removes the mirrored `Resources/build` folder.

## Why This Fixes The Issue
- A single flat `Resources/build` folder is easier to consume directly when installing or packaging from local build artifacts.
- Copying both project outputs into that shared folder means the configurator executable and transport-agent DLL are already colocated, which removes the need to gather files from multiple subdirectories.

## Public Contract Impact
- No code or public API changes.
- No changes to project output paths consumed by Visual Studio or existing compile behavior beyond the additional mirrored artifacts.

## Validation
- XML/MSBuild file added with a minimal repo-wide target that only depends on standard `Build` and `Clean` targets plus `$(TargetDir)`/`$(OutputPath)`.
- Full solution build could not be executed in this environment because `dotnet`, `msbuild`, and `xbuild` are unavailable.

## Risks / Edge Cases
- The mirror target copies from `$(TargetDir)` only, so if a future build process emits required packaging files outside the standard output directory they will not appear in `Resources/build` until explicitly included.
- Both projects now copy into the same flat folder, so duplicate filenames will be overwritten by whichever project builds last.
- `Clean` removes the entire mirrored `Resources/build` folder; if only one project is cleaned, the other mirrored files are removed too.

## Handoff To TestEngineer
- Verify these build scenarios:
  1. `Build Solution` creates `Configuration.DkimSigner.exe` directly under `Resources/build`.
  2. `Build Solution` creates `ExchangeDkimSigner.dll` directly under `Resources/build`.
  3. `Clean Solution` removes `Resources/build`.
  4. Local install/packaging from `Resources/build` works without collecting files from subfolders.

## Handoff To QaEngineer
- Confirm regression scope is limited to build artifact mirroring.
- Verify no change to default VS debugging/build behavior from the original `bin` folders.
- Confirm `Resources/build` now contains the combined install payload directly at the top level.

---

## Scope
Upgrade vulnerable NuGet dependencies reported during compile/package vulnerability checks.

## Classification
STANDARD

## Files Changed
- Src/Exchange.DkimSigner/Exchange.DkimSigner.csproj
- Src/Configuration.DkimSigner/Configuration.DkimSigner.csproj

## What Changed
1. Updated `MimeKit` from `4.3.0` to `4.15.1` in both projects.
2. Added an explicit `PackageReference` to `BouncyCastle.Cryptography` version `2.6.2` in both projects to satisfy MimeKit's transitive minimum and force a non-vulnerable resolution.

## Why This Fixes The Issue
- Advisory `GHSA-gmc6-fwg3-75m5` requires MimeKit >= `4.7.1`.
- Advisory `GHSA-g7hc-96xr-gvvx` requires MimeKit >= `4.15.1`.
- Advisories `GHSA-v435-xc8x-wvr9`, `GHSA-m44j-cfrm-g8qc`, and `GHSA-8xfc-gm6g-vgpv` require BouncyCastle.Cryptography >= `2.3.1`; `2.6.2` is pinned to also satisfy MimeKit `4.15.1` transitive dependency constraints.
- Pinning these minimum safe versions should clear the listed vulnerability warnings while keeping the change set minimal.

## Public Contract Impact
- No intended public API or behavioral contract change.
- Dependency graph changes only.

## Validation
- Verified both edited `.csproj` files have no editor diagnostics.
- Local package restore/build verification could not be executed in this environment because `dotnet` is not installed.

## Risks / Edge Cases
- MimeKit `4.15.1` is a significant jump from `4.3.0`; minor runtime behavior differences are possible and should be validated in CI/build host.
- If external tooling pins older transitive versions via lock files outside this repo, those environments may still need lock refresh.

## Handoff To TestEngineer
- Validate `restore` and `build` on an environment with .NET SDK.
- Run vulnerability scan (`dotnet list package --vulnerable --include-transitive`) and confirm the five reported advisories are resolved.
- Smoke test signing flow for DKIM and key import paths using existing manual test assets under `Resources/Tests`.

## Handoff To QaEngineer
- Confirm remediation scope is limited to dependency version updates in project metadata.
- Confirm release notes mention dependency-security uplift.
- Confirm no packaging/install regressions from updated transitive closure.

---

## Scope
Add a Domain Settings action to deploy `settings.xml` and the full `keys` folder to multiple Exchange servers from a `servers.csv` file.

## Classification
STANDARD

## Files Changed
- Src/Configuration.DkimSigner/MainWindow.cs
- Src/Configuration.DkimSigner/MainWindow.Designer.cs

## What Changed
1. Added a new `Deploy from CSV` button in the Domain Settings section (`gbxDomainDetails`) and wired it to a new click handler.
2. Implemented CSV target loading (`Host`, `Path`) with support for quoted fields, optional trailing comma, and duplicate row deduplication.
3. Added UNC path mapping logic so a row like `P01-MBX-01\, C:\Program Files\Exchange DkimSigner` deploys to `\\P01-MBX-01\C$\Program Files\Exchange DkimSigner`.
4. Implemented deployment flow that copies local `settings.xml` and recursively copies all files from local `keys` to each remote target.
5. Added per-server success/failure aggregation and a final summary message to make partial failures visible.

## Why This Fixes The Issue
- The new Domain Settings action allows one-click fan-out deployment to many servers listed in `servers.csv`.
- Deployment now scales from a single host to a fleet without manually repeating file copy operations on each server.

## Public Contract Impact
- No shared library/API contract changes.
- UI surface changed by adding one button and behavior in `Configuration.DkimSigner` only.

## Validation
- Editor diagnostics: no errors in modified files.
- Attempted `dotnet build DkimSigner.sln` in this environment failed with `MSB3644` because .NET Framework 4.8 reference assemblies are not installed (Linux host).

## Risks / Edge Cases
- Remote admin share access (`\\<host>\C$`) requires appropriate permissions and network access.
- Non-drive-rooted local paths in CSV are rejected (path must be local absolute like `C:\...` or UNC).
- Large `keys` directories can make deployment take noticeable time because copies are sequential.

## Handoff To TestEngineer
- Validate end-to-end deployment from Domain Settings with a sample `servers.csv`:
  1. `Host,Path` header + multiple rows with quoted paths.
  2. Confirm remote `settings.xml` overwrite behavior.
  3. Confirm recursive copy of all files/subfolders under `keys`.
  4. Validate mixed outcome handling when one server is unreachable.
- Verify permissions behavior when running with/without required rights on admin shares.

## Handoff To QaEngineer
- Confirm scope limited to Configuration UI and deployment helper logic.
- Validate no regressions in existing domain save/generate/select/check-DNS workflows.
- Confirm operator guidance/documentation includes expected CSV format and required permissions.
