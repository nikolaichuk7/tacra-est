#!/usr/bin/env python3
"""Print the drills of a run as a Markdown table, plus sizes, timings and the burst, so that
docs/RESULTS.md is filled from the file and not from memory.

    python3 scripts/summarize_drills.py evidence/<stamp>/drills.json
"""
import json
import statistics
import sys

TEXT = {"D1": "PR", "D2": "PR", "D3": "PR", "D3b": "PR", "D4": "-00", "D5": "PR", "D5b": "PR", "D6": "-00", "D7": "PR", "D9": "PR", "D10": "-00",
        "D11": "PR", "D12": "PR", "D13": "PR", "D14": "PR", "D15": "PR", "D16": "PR", "D17": "PR", "D18": "PR", "D19": "PR", "D20": "-00", "D21": "PR"}
LABEL = {
    "D1_enroll_honest": "D1 honest enrollment at S1, present-nonce",
    "D2_retrieve_honest": "D2 honest retrieval at S1, present-nonce",
    "D3_rrp_substitution_held_id": "D3 RRP substitution, identifier held by the Attester (conduit says CA1, carries to S2)",
    "D3b_rrp_substitution_id_from_response": "D3b RRP substitution, identifier taken from S2's response",
    "D4_rrp_substitution_draft00": "D4 RRP substitution",
    "D5_bundle_substitution_pr_text": "D5 bundle substitution, base-mode container",
    "D5b_bundle_substitution_forged_auth_pr_text": "D5b bundle substitution, forged hpke-auth under the attacker's key",
    "D6_bundle_substitution_draft00": "D6 bundle substitution",
    "D7_handle_replay": "D7 Handle replay",
    "D9_target_substitution_pr_text": "D9 target substitution (conduit initiates for another Target)",
    "D10_target_substitution_draft00": "D10 target substitution",
    "D11_present_epoch_honest": "D11 honest enrollment, present-epoch",
    "D12_present_epoch_moved": "D12 present-epoch, epoch moved between the legs",
    "D13_absent_epoch_honest": "D13 honest enrollment, absent-epoch",
    "D14_absent_timestamp_honest": "D14 honest enrollment, absent-timestamp",
    "D15_absent_timestamp_local_initiate": "D15 absent-timestamp, attest-initiate completed locally",
    "D16_absent_timestamp_stale": "D16 absent-timestamp, clock 120 s behind, max_age 60",
    "D17_absent_none_honest": "D17 honest enrollment, absent-none",
    "D18_absent_timestamp_retrieval": "D18 honest retrieval, absent-timestamp",
    "D19_shared_freshness_two_rrps": "D19 one absent-timestamp request posted to S1, then to S2",
    "D20_shared_freshness_two_rrps_draft00": "D20 one absent-timestamp request posted to S1, then to S2",
    "D21_absent_timestamp_replay_same_rrp": "D21 one absent-timestamp request posted to S1 twice",
}


def main(path):
    d = json.load(open(path))
    D = d["drills"]
    print("Run %s, TEE %s, host %s\n" % (d["stamp"], d["tee"], d.get("host")))
    print("| drill | text | outcome | evidence ms | round trip ms |")
    print("|---|---|---|---|---|")
    import re
    def order(k):
        m = re.match(r"D(\d+)(b?)_", k)
        return (int(m.group(1)), m.group(2)) if m else (999, k)
    for k, v in sorted(D.items(), key=lambda kv: order(kv[0])):
        if k.startswith("D8"):
            continue
        short = k.split("_")[0]
        if k == "D7_handle_replay":
            print("| %s | PR | first: %s; second: %s %s | | |" % (LABEL[k], v["first"], v["second_status"], (v.get("second_error") or {}).get("error")))
            continue
        if k == "D12_present_epoch_moved":
            print("| %s | PR | first: %s %s; retry: %s | | |" % (LABEL[k], v["first_status"], (v.get("first_error") or {}).get("error"), v["retry"]))
            continue
        if k in ("D19_shared_freshness_two_rrps", "D20_shared_freshness_two_rrps_draft00"):
            print("| %s | %s | S1: %s; S2: %s | | |" % (LABEL[k], TEXT.get(short, ""), v["at_S1"], v["at_S2"]))
            continue
        if k == "D21_absent_timestamp_replay_same_rrp":
            print("| %s | PR | first: %s; again: %s | | |" % (LABEL[k], v["first"], v["again_at_S1"]))
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
    log1 = [x for x in d.get("server_logs", {}).get("S1", []) if x.get("outcome") == 200]
    if log1:
        x = log1[0]
        print("\nAttester platform: %s, form %s, chip %s…, report_id %s…, measurement %s…; checks %s" % (
            x.get("platform"), x.get("platform_form"), x.get("chip_id"), x.get("report_id"), x.get("measurement"), x.get("checks")))


if __name__ == "__main__":
    sys.path.insert(0, __file__.rsplit("/", 2)[0] + "/impl")
    main(sys.argv[1])
