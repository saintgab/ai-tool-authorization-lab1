# 0.5 — Preserve original results and version the follow-up

- Add explicit original/v1.1 protocols. Original keeps the historical no-op; v1.1 starts the reopen case closed.
- Label any non-original protocol or nonzero-temperature experiment exploratory and record initial state.
- Forward run_live.sh CLI options so the user can run a labeled temperature-0.7 follow-up.
- Add a filename-only secret-candidate scanner and provisional first-run notes, with prompt-policy and denominator corrections.
- No prompt ablation or live-outcome tuning. 121 core tests passed, five optional UI tests skipped.
- Full original live artifacts have not yet been supplied; user-pasted outputs are explicitly identified as the evidence source.

# 0.4 — Deterministic scope check and correlated audit evidence

- Keep Bob-authored comment fixtures and trusted provenance explicit; no ownership-based attribution.
- Compare proposals against application-declared task scope; any mutation is off-task for summarization.
- Compute a short banner, make rejection primary, require a confirmation checkbox, and enforce off-task confirmation in the backend.
- Link proposal, denial, approval/rejection, and commit by server-generated request ID; log ISO-8601 UTC timestamps.
- Record explicit off-task approvals with provenance as evidence of deliberate override.
- Add measured review-control fixtures and a hidden-input local live-run script.
- 116 tests pass; 5 optional Streamlit tests skip here. Real-model experiment remains unrun without credentials.

# 0.3 — Make the attacker and source explicit

- Move poison into separately stored comments authored by Bob, with an explicit comment-only grant on Alice's ticket 3.
- Add tested comment ingress that derives authorship from the authenticated session; Bob cannot approve or update Alice's target ticket.
- Add subtle duplicate-ticket wording as case 12, separately scored from overt case 11.
- Build review provenance from the actual stored comment, including author, excerpt, variant, and original task.
- Automatically select and lock Alice for the same-user scenario; clear stale pending review when controls change.
- Rename the run button and caption, add explicit Reject, refresh ticket table after action, and request minimal Streamlit toolbar.
- 106 non-UI tests pass; three optional Streamlit interaction tests skip here because Streamlit is unavailable. Stub attempts: 60 per mode. Live experiment: 70 requests by default; not run.

# 0.2 — Correct the threat model and live experiment

- Add same-user poisoned-document case 11 and change the mid-conversation target to the user's own ticket.
- Make the approval limitation and rubber-stamping behavior explicit and tested.
- Show original user task and server-supplied input exposure on approval review.
- Replace instruction-following injection prompts with benign requests; move ticket descriptions out of system messages into tool results.
- Add ten model-assisted legitimate cases, narrow predetermined scoring, and separate task/backend failure counters.
- Route stub and live proposals through dispatch_model without harness tokens; retain direct executor binding tests separately.
- Log denials after rollback and commits within the update transaction.
- Deny malformed proposals; support null tool_calls and timeout reporting.
- Record source hashes and run settings with live evidence.
- Replace old 50-attempt results with 55-attempt stub results. Expanded suite: 95 tests passed.
- Real-model results remain unmeasured because no API key was available in the build environment. No claim of empirical susceptibility is made.
