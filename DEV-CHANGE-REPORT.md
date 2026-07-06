# DEV CHANGE REPORT

## Scope
Fix false-negative DNS public key validation in domain settings and ensure validation covers all selectors shown in suggested DNS output.

## Classification
STANDARD

## Files Changed
- Src/Configuration.DkimSigner/MainWindow.cs

## What Changed
1. Reworked `btDomainCheckDNS_Click` to validate all DKIM selector names present in suggested DNS records (`Name:` entries), instead of validating only the selector from the selector textbox.
2. Replaced fragile regex-on-whole-text comparison with per-record extraction:
   - Parse expected key per DNS name from suggested `Data:` lines.
   - Query TXT records per DNS name.
   - Extract `p=` tag value from the matching DNS TXT record.
   - Canonicalize values before comparison (trim quotes/whitespace).
3. Improved output behavior:
   - `Existing DNS` now shows one block per checked selector/domain name.
   - Status label reports all-match vs specific per-selector mismatches.

## Why This Fixes The Issue
- Previous logic could select the wrong expected `p=` value when suggested text contained multiple records, causing a mismatch even when DNS was correct.
- New logic compares each queried name against the corresponding expected key, eliminating cross-selector comparison errors.
- Validation now includes both selectors when both are present in suggested DNS entries.

## Public Contract Impact
- No changes to persisted config schema or public contracts (`DomainElement`, `Settings`).

## Validation
- Local file diagnostics: no errors in `MainWindow.cs`.
- Full solution build could not be executed in this environment because `dotnet`, `msbuild`, and `xbuild` are unavailable.

## Risks / Edge Cases
- If suggested DNS text does not include parsable `Name:` + `Data:` records, the check falls back to the current selector domain only.
- DNS servers returning multiple unrelated TXT records are handled by selecting the first record containing a parsable `p=` tag.

## Handoff To TestEngineer
- Verify these scenarios in UI:
  1. Dual selector setup: both RSA and Ed25519 records present and correct.
  2. Only one selector present in DNS.
  3. DNS TXT record present but missing `p=`.
  4. Quoted/chunked TXT responses with whitespace around tags.
  5. Mixed resolver options (Local/Google/Cloudflare) and Direct NS check toggle.

## Handoff To QaEngineer
- Confirm regression scope is limited to DNS validation display/comparison in domain settings.
- Review UI messaging for multi-selector mismatch readability.
- Ensure no behavior change in save/load domain settings and signer runtime behavior.
