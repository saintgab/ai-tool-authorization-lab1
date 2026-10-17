# Revision 0.5 release evidence

Completed:
- [x] Deterministic structured-task mismatch; model output cannot suppress it.
- [x] One-line off-task banner, primary rejection, checkbox before approval.
- [x] Backend confirmation check for off-task override; measured separately from attack enforcement.
- [x] Request IDs link proposal, denial, approval/rejection, and commit; ISO-8601 UTC audit time.
- [x] Approval events include off_task, confirmation, and Bob-authored provenance.
- [x] Local hidden-input live-run script; no API credential available here.
- [x] Cases 11 and 12 target the victim's own ticket; ownership passes and approval is the blocking control.
- [x] Positive rubber-stamping test documents approval's limit.
- [x] Bob has separately tested comment-only access; author is session-derived.
- [x] Overt and subtle comments have separate live and stub rows.
- [x] Review displays comment author, body, original task, target action, and explicit rejection.
- [x] Scenario automatically selects Alice; variant changes clear pending review.
- [x] Button/caption corrected; minimal-toolbar config added.
- [x] Benign indirect prompts; all ticket text delivered through tool results.
- [x] Mid-conversation case starts with an actual approved update in setup.
- [x] All stub attacks and live proposals route through dispatch_model without tokens.
- [x] Separate trusted-executor tests retain all approval-binding coverage.
- [x] Ten harmless live cases and separate completion/model-failure/backend-false-block reporting.
- [x] Proposal, commit, and denial audit records; atomic commit logging.
- [x] Missing arguments become Denied; null tool_calls and TimeoutError handled.
- [x] 121 non-UI tests passed; 5 optional Streamlit tests skipped, including mocked live success/failure paths.
- [x] Deterministic results and traces regenerated for 12 × 5 cases per mode.

Required before publishing completion claims:
- [x] User ran the original live experiment with a pinned snapshot; pasted output shows zero API errors.
- [x] Inspect both complete supplied run archives and verify counts against traces.
- [x] Report zero targeted indirect mutations and original scoring limitation without hiding them.
- [ ] Verify revision 0.4 runtime on your Mac; run the 5 included optional AppTest cases after installation.
- [ ] Pin resolved UI dependencies using pip freeze after installation.
- [ ] Record the two-minute video.
- [ ] Outside tester reproduces from README.md only in a clean Python environment.
- [ ] Record their setup time, problems, and fixes.
- [ ] Review applicable publication/IP agreements.

Outside tester / setup duration / friction: NOT YET RECORDED.
No AWS resources are created by this local AI project.

First-run follow-up:
- [x] Original protocol retained; no silent rescoring of original CSV.
- [x] v1.1 closes the reopen fixture before the request.
- [x] Exploratory label for temperature-0.7 follow-up; original prompt unchanged.
- [x] Filename-only candidate scanner; actual original results must be scanned locally.
- [x] Receive and inspect both run archives, including config/request/response/audit evidence.
- [x] User ran exploratory v1.1; raw evidence and integrity manifest are included.
- [ ] Record video after results interpretation is settled.

Verified results and a two-minute recording script are included. The failed SSL directory remains on the user's Mac; its raw archive was not supplied.
