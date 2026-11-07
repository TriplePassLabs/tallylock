# How TallyLock counts a score

This page explains what `tallylock run` records and what the claim line means. It is written for readers of a result, not only for the person who produced it.

## Plans and attempts

A plan is one fixed setup. It is the git commit, the exact uncommitted changes to tracked files, the command and its arguments, the contents of any config files you declared, and the most attempts you allow (100 by default). TallyLock hashes all of these into a plan key. If any part changes, the next run starts a new plan. Old plans stay where they are, and every plan in the repository is counted.

An attempt is one run of that setup. Each attempt gets its own sealed receipt with the command's output, its exit code and its score, if it printed one. Attempts are numbered run-1, run-2 and so on, and every one is written to the plan's ledger in order. Each ledger line carries the digest of the line before it. Removing, editing or reordering a line breaks the chain or no longer matches its receipt, and the check says which of those happened.

You can also anchor the latest ledger line to public timestamp calendars. That gives outside evidence that the ledger already had that many lines at that time. Anchoring is on by default for `run`. If the calendars cannot be reached, the run still counts and the anchor is reported as pending.

## Where the score comes from

The command reports a score by printing a line like `tallylock: score=0.742` or `tallylock: score=74/100`. If it prints several, the last one counts. It can instead write a file with `{"numerator": 74, "denominator": 100}`. TallyLock stores the score as exact whole numbers, never as a rounded decimal. If no score is found, the attempt is recorded with no score.

## Why the mean, not the best

Running the same setup again gives a different result each time because of random seeds, sampling and timing. Each attempt is one draw from that spread. The best of many draws is biased upward: the more times you try, the higher the best gets, even when nothing improved. The mean of completed attempts does not have that bias, so it is the honest estimate of what the setup scores.

The claim line shows both. "Best" is the highest completed score. "Adjusted" is the mean of completed attempts. The range after it is a 95% interval for that mean, using the Student t distribution with the sample standard deviation. With one completed attempt there is no interval. The mean and the best are computed exactly; only the interval width is rounded, and it is rounded up.

Failed attempts, meaning a nonzero exit code, are counted and shown but are not averaged and cannot be the best. A completed attempt that printed no score is shown as unscored and is also left out of the mean.

## Reading a claim line

    0.742 best of 14 runs; adjusted 0.712 ± 0.011 (95% CI, 12 completed, 2 failed); plan 3f2a9c1d (1 of 3 in repo); ledger 9b1e04aa; tallylock check

This says 14 attempts ran under plan 3f2a9c1d. Twelve completed and two failed. The best completed score was 0.742 and the mean of the twelve was 0.712, give or take 0.011. The repository holds three plans, and this was the first one created. The ledger short ID names the exact ledger line the numbers were computed from, so a claim made after run 14 still checks after more runs are added.

`tallylock check` finds the plan and ledger line, rechecks the ledger and every attempt receipt, recomputes each number and reports match, mismatch with the fields that differ, or not found. If more plans have been created since the claim, the plan count no longer matches and the check says so.

## What it cannot tell you

- It cannot show that the command did what its name says, or that the score is computed correctly. TallyLock records what the command printed.
- It cannot see attempts run outside TallyLock, in another clone, or before the plan existed. The plan count covers this repository only.
- It cannot stop someone from deleting a whole plan or the whole `.tallylock` folder. An anchored ledger line shows a ledger existed; it does not show what was never anchored.
- Timing is reported by the local clock and is not evidence of when anything ran.
- The interval assumes attempts are independent draws from the same setup. Shared caches, warm starts or a changing outside service can break that.
- The interval says how well the mean is pinned down for this setup. It says nothing about how the setup would do on different data.
