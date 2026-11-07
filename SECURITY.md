# Security policy

## Report a problem privately

Please do not open a public issue for a security problem. Use GitHub private security advisories instead.

1. Open the repository's Security tab on GitHub.
2. Choose "Report a vulnerability".
3. Describe what you found, how to reproduce it, and which version you used.

Reports stay private until a fix is ready. You will get a first reply within a few days.

## What counts

TallyLock checks that a receipt has not been changed after it was frozen. A report is in scope if it shows a way to make a changed receipt pass verification, to make verification run code or reach the network, or to write outside the selected receipt folder.

TallyLock does not prove that a run was honest or which model produced it. Those limits are documented in the threat model and are not vulnerabilities.

## Supported versions

Only the latest release receives fixes.
