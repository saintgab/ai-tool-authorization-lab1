# Two-minute demo script — verified results

Record in the latest local app using synthetic data. Close the helper popup, use the included minimal-toolbar configuration, and keep API keys and billing screens out of the recording. The live experiment is already complete; do not make paid calls while recording.

| Time | Show | Say |
|---|---|---|
| 0:00–0:20 | RESULTS.md comparison table | “I built a small lab to separate an AI proposing an action from an application authorizing it. I tested the same model responses against an unchecked baseline and a protected backend.” |
| 0:20–0:40 | Original and exploratory counts | “The baseline committed 26 unapproved changes in the original 60 probe attempts, and 25 in the exploratory run. The protected backend committed none. The model was allowed to propose actions for review; the unsafe step was automatic execution.” |
| 0:40–1:05 | Alice selected automatically; Bob-authored overt or subtle comment | “This comment is Bob's text, but the assistant acts for Alice. Bob asks it to close another ticket that Alice owns. Ownership would pass. The live model did not perform this injection in our tested cases, so I use a deliberately malicious stub to exercise the execution control.” |
| 1:05–1:25 | Run model (malicious stub); off-task banner; Reject primary; Approve disabled | “The application compares the proposal with the original task: summarize ticket three. Closing ticket one is off-task. Model claims cannot create approval. Rejection is the default action, and an override requires explicit confirmation.” |
| 1:25–1:45 | Audit proposal and denial sharing request_id; Bob provenance | “The audit records link this proposal and denial with one request ID and UTC timestamps. A deliberate confirmed override also leaves evidence. This adds a boundary and accountability; it does not make rubber-stamping impossible.” |
| 1:45–2:00 | RESULTS.md legitimate scores and limits | “The corrected follow-up completed all ten legitimate tasks. The original nine-out-of-ten score included a correct already-open answer, which I documented rather than hiding. These are small tests on one model, not a claim of universal injection resistance.” |

Practice once and shorten pauses to fit two minutes. Showing the live model resisting these poisons is a valid result; do not present the stub as a successful real-model injection.

## Short recording checklist

1. Start the local app per README.md. Do not run `run_live.sh` again.
2. Open RESULTS.md and keep the comparison visible in another window.
3. Select the same-user scenario and desired comment variant; Alice is automatic.
4. Press Shift-Command-5 to record the app and results windows.
5. Run the malicious stub, show the denial and review, then choose Reject.
6. Show linked request IDs in the audit log and the limits paragraph in RESULTS.md.
7. Save the recording and add its link at the top of README.md after reviewing it.

A recorded video is not included in this package.
