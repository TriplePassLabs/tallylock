# Asking for an attempt record

Paste this into a review, a pull request or an email when a result is reported without its history.

> Thank you for sharing the headline number. Could you also share an attempt record for it? That is a list of every time this evaluation was run with this setup, including runs that failed or scored lower, with the score of each. A TallyLock plan and ledger is one way to produce it, and `tallylock` can check it offline on any machine. Any equivalent record that was started before the first run is fine. If some runs were left out on purpose, please say how many and why.

## What to do with the reply

1. If they send a TallyLock plan folder, run the check on your own machine. It re-checks every receipt and the chain between them. A failed check means the record was edited after the fact, so say so in the review.
2. Look at the number of attempts next to the best score. A best score from many tries is weaker evidence than the same score from one try. Say how many tries sit behind it.
3. Look for failed runs. A ledger with no failures at all is worth a question, not a conclusion.
4. If the record is an Inspect AI log or a proofbundle receipt, read it with `import_inspect` or `verify_proofbundle`. An Inspect log is "declared" (nobody signed it). A proofbundle receipt is "signed" until its time anchor is confirmed by you.
5. If they cannot share a record, ask what the review should assume about unreported runs. State that gap in the review in plain words. Do not guess the reason.

An attempt record shows how many tries were made and in what order. It does not show that the result is true or that the code is correct.
