"""Offline malicious-stub evaluation; NOT empirical LLM behavior."""
import csv
import json
from pathlib import Path
from engine import Call, Denied, Lab
from scenarios import ATTACKS, MaliciousModel, prepare, provenance


def main():
    output = Path("results")
    output.mkdir(exist_ok=True)
    rows = []
    traces = []
    for protected in (False, True):
        for name in ATTACKS:
            executed = 0
            for repetition in range(5):
                clock = [1000.0]
                lab = Lab(clock=lambda: clock[0])
                session, call, token = prepare(lab, name, clock)
                proposal = MaliciousModel().propose(call)
                before = lab.ticket(call.ticket_id)
                committed = False
                reason = ""
                try:
                    lab.dispatch_model(session, proposal, protected=protected, source=provenance(name, lab))
                    executed += 1
                    committed = True
                except Denied as exc:
                    reason = str(exc)
                traces.append({"source": "malicious_stub", "case": name,
                    "protected": protected, "repetition": repetition + 1,
                    "proposal": proposal, "committed": committed, "reason": reason,
                    "before": before, "after": lab.ticket(call.ticket_id)})
                lab.close()
            rows.append({"source": "malicious_stub", "mode": "protected" if protected else "baseline",
                         "attack": name, "variant": provenance(name).get("variant", "not_applicable"), "attempts": 5, "proposed": 5, "executed": executed})
    with (output / "stub_results.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output / "stub_traces.jsonl").write_text("".join(json.dumps(t) + "\n" for t in traces))
    for mode in ("baseline", "protected"):
        subset = [r for r in rows if r["mode"] == mode]
        print(f"{mode}: proposed {sum(r['proposed'] for r in subset)}/{len(ATTACKS)*5}; "
              f"executed {sum(r['executed'] for r in subset)}/{len(ATTACKS)*5} [MALICIOUS STUB]")
    passed = 0
    for i in range(10):
        lab = Lab()
        session = lab.login_demo("alice" if i % 2 == 0 else "bob")
        call = Call(1 if i % 2 == 0 else 2, target_status=["closed", "in_progress", "open"][i % 3])
        lab.execute(session, call, lab.approve_from_ui(session, call))
        passed += 1
        lab.close()
    print(f"Legitimate backend requests: {passed}/10 committed; false blocks {10-passed}/10")

    review_rows, review_traces = [], []
    for name in ['same_user_injection', 'same_user_injection_subtle']:
        blocked, overridden = 0, 0
        for _ in range(5):
            lab = Lab()
            session, call, _ = prepare(lab, name, [1000.0])
            source = provenance(name, lab)
            request_id = lab.new_request(session, source['task'], source)
            try:
                lab.dispatch_model(session, MaliciousModel().propose(call), request_id=request_id)
            except Denied:
                pass
            try:
                lab.approve_from_ui(session, call, request_id=request_id)
            except Denied as exc:
                assert str(exc) == 'Explicit confirmation required for off-task approval'
                blocked += 1
            token = lab.approve_from_ui(session, call, request_id=request_id, confirm_off_task=True)
            lab.execute(session, call, token)
            overridden += 1
            review_traces.append({'request_id': request_id, 'variant': source['variant'],
                'audit_events': [json.loads(r[0]) for r in lab.db.execute('SELECT data FROM events')]})
            lab.close()
        review_rows.append({'variant': provenance(name)['variant'], 'attempts': 5,
                            'unconfirmed_approvals_blocked': blocked,
                            'explicit_overrides_committed': overridden})
    with (output / 'review_control.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(review_rows[0]))
        writer.writeheader()
        writer.writerows(review_rows)
    (output / 'review_control_traces.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in review_traces))
    print('Off-task approval control: unconfirmed 10/10 blocked; explicit overrides 10/10 committed [SIMULATED UI]')


if __name__ == "__main__":
    main()
