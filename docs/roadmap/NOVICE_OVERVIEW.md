# TallyLock: easy to start, your choice of trust

Proposed design, not commands available in the current release.

TallyLock keeps a plan, its output files and its declared results together in a portable receipt. It checks whether those bytes agree. Optional Bitcoin timestamp evidence helps show that a commitment existed by a block; it does not prove that someone ran an experiment honestly or at an exact time.

You should not need to download Bitcoin to use TallyLock.

| Choice | Good for | Tradeoff |
| --- | --- | --- |
| Public service, recommended | Quick timestamp checks with small internet requests | Trust the named service's Bitcoin view; it sees your IP and requested blocks |
| Your existing Bitcoin node | An independent source you already maintain or trust | You manage that node and its availability |
| Offline only | Local integrity checks and selected saved evidence | Saved evidence cannot establish today's chain state |
| New managed Bitcoin node, later optional feature | Users who deliberately want their own infrastructure | Large initial download, storage, electricity and maintenance; pruning reduces storage, not initial transfer |

Install the small CLI using a supported package manager or Python environment. That installer chooses where the program lives. Then `tallylock setup` configures how you want to use it. Setup does not install Bitcoin or start a service.

```text
$ tallylock setup
How would you like to check timestamps?
  1 Public service (recommended)
  2 My existing Bitcoin Core node
  3 Offline only
Choice [1]: 1
Service [Blockstream]: Blockstream
Trust this service's Bitcoin view? [yes]: yes
Use normal configuration/evidence locations? [yes]: yes
Open advanced settings (including optional new-node planning)? [no]: no
Save profile "everyday"? [yes]: yes
Saved. No network request was made.

Next online check:
  tallylock verify ./receipt --online --profile everyday --human
```

Advanced path and node settings are available when wanted. Ordinary users do not have to answer a page of directory questions. Receipt files stay where you explicitly save them. Offline checks remain available without setup.

The first useful alpha focuses on this flow, diagnosis and clear results. Twenty roadmap features are spread across four phases; they do not all have to ship first. New-node installation comes later and shows updated download/storage estimates, limits and a separate approval before any large work. No paid subscription or background service is required.

Target, not a measured promise: get from a working installation to a first local checked receipt within five active minutes. Package downloads and Bitcoin confirmation waits are measured separately. Current qualification is Linux with Python 3.11–3.13; broader OS support follows actual testing.

Phase 1 includes plain-language results through proposed `--human`: “Receipt integrity checked. Timestamp matches Bitcoin data reported by Blockstream. Bitcoin consensus was not independently validated. Execution claims remain unverified.” Existing commands keep JSON output by default for automation. Proposed `--human` and `--json` cannot be combined. Rich shareable HTML comes later; understandable CLI results do not wait for it.
