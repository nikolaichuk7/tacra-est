#!/usr/bin/env python3
"""Print the drills of a run as a Markdown table, plus sizes, timings and the burst, so that
docs/RESULTS.md is filled from the file and not from memory.

    python3 scripts/summarize_drills.py evidence/<stamp>/drills.json
"""
import json
import statistics
import sys

TEXT = {"D1": "PR", "D2": "PR", "D3": "PR", "D4": "-00", "D5": "PR", "D5b": "PR", "D6": "-00", "D7": "PR"}
LABEL = {
    "D1_enroll_honest": "D1 honest enrollment at S1",
    "D2_retrieve_honest": "D2 honest retrieval at S1",
    "D3_server_substitution_pr_text": "D3 server substitution (conduit says S1, carries to S2)",
    "D4_server_substitution_draft00": "D4 server substitution",
    "D5_bundle_substitution_pr_text": "D5 bundle substitution, base-mode container",
    "D5b_bundle_substitution_forged_auth_pr_text": "D5b bundle substitution, forged hpke-auth under the attacker's key",
    "D6_bundle_substitution_draft00": "D6 bundle substitution",
    "D7_handle_replay": "D7 Handle replay",
}


def main(path):
    d = json.load(open(path))
    D = d["drills"]
    print("Run %s, TEE %s, host %s\n" % (d["stamp"], d["tee"], d.get("host")))
    print("| drill | text | outcome | evidence ms | round trip ms |")
    print("|---|---|---|---|---|")
    for k, v in D.items():
        if k.startswith("D8"):
            continue
        short = k.split("_")[0]
        if k == "D7_handle_replay":
            print("| %s | PR | first: %s; second: %s %s | | |" % (LABEL[k], v["first"], v["second_status"], (v.get("second_error") or {}).get("error")))
            continue
        t = v.get("timings_ms") or {}
        rt = t.get("enroll_ms") or t.get("retrieve_ms")
        print("| %s | %s | %s %s | %s | %s |" % (LABEL.get(k, k), TEXT.get(short, ""), v.get("status", ""), v.get("outcome"),
                                              "%.1f" % v["evidence_ms"] if v.get("evidence_ms") is not None else "", "%.1f" % rt if rt else ""))
    print("\nSizes (bytes): %s" % json.dumps(d.get("sizes_bytes"), sort_keys=True))
    # server-side timings for the honest drills
    for name in ("S1",):
        entries = [e for e in d.get("server_logs", {}).get(name, []) if e.get("outcome") == 200]
        if entries:
            v = [e["ms_verifier"] for e in entries if "ms_verifier" in e]
            print("Server %s: %d successful requests; Verifier median %.1f ms (min %.1f, max %.1f); CA/Vault median %.1f ms" % (
                name, len(entries), statistics.median(v), min(v), max(v),
                statistics.median([e.get("ms_ca") or e.get("ms_vault") or 0 for e in entries])))
    b = D.get("D8_report_burst")
    if b:
        print("\nBurst: n=%d, median %.2f ms, p95 %.2f ms, max %.1f ms, total %.1f s; slow (>1 s): %s" % (
            b["n"], b["median_ms"], b["p95_ms"], b["max_ms"], b["total_s"], [(s["index"], s["ms"]) for s in b["slow_reports"]]))
    e = D.get("D1_enroll_honest", {})
    ev = (e.get("enrollment_request") or {}).get("evidence") or {}
    if ev.get("type") == "sev-snp":
        from common import b64u_dec, parse_snp_report  # noqa
    log1 = [x for x in d.get("server_logs", {}).get("S1", []) if x.get("outcome") == 200]
    if log1:
        x = log1[0]
        print("\nAttester platform: %s, form %s, chip %s…, report_id %s…, measurement %s…; checks %s" % (
            x.get("platform"), x.get("platform_form"), x.get("chip_id"), x.get("report_id"), x.get("measurement"), x.get("checks")))


if __name__ == "__main__":
    sys.path.insert(0, __file__.rsplit("/", 2)[0] + "/impl")
    main(sys.argv[1])
