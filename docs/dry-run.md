# Dry run

Plan: 3 test repos under `kumarswamyg2005` created from `tests/fixtures`:

1. `vibeguard-test-lovable` — vulnerable Lovable-style app (expects VG001,
   VG002 fixable, VG004, VG008, VG009, VG010)
2. `vibeguard-test-bolt` — vulnerable Bolt-style app (expects VG002
   decision issue, VG006, VG007, VG008)
3. `vibeguard-test-secure` — already-secure app (expects onboarding only)

Then: install the GitHub App on all three → `gh workflow run tick.yml` →
record the resulting PR/issue links here.

## Results

_To be filled in after the GitHub App exists and the first real tick runs._

- App install URL:
- Onboarding PRs:
- Fix PRs:
- Decision issues:
- Tick run logs:
