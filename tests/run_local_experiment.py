"""Record the owned weak-baseline/fixed-client comparison as machine evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

from redirect_credential_boundary import RedirectClient, RedirectLimitError, RedirectLoopError

from lab_support import LoopbackLab


AUTH = "Bearer SYNTHETIC_LAB_TOKEN"
COOKIE = "lab_session=SYNTHETIC_LAB_COOKIE"
HEADERS = {"Authorization": AUTH, "Cookie": COOKIE}


def weak_loopback_follow(lab: LoopbackLab) -> int:
    """Deliberately unsafe test baseline; restricted to this lab's two ports."""
    first = http.client.HTTPConnection("127.0.0.1", lab.a_port, timeout=2)
    try:
        first.request("GET", "/cross", headers=HEADERS)
        response = first.getresponse()
        location = response.getheader("Location")
        response.read()
    finally:
        first.close()
    if response.status != 302 or not location:
        raise AssertionError("owned A server did not issue the expected redirect")
    parsed = urlsplit(location)
    if parsed.hostname != "127.0.0.1" or parsed.port != lab.b_port or parsed.scheme != "http":
        raise AssertionError("baseline destination escaped the owned loopback lab")
    second = http.client.HTTPConnection("127.0.0.1", lab.b_port, timeout=2)
    try:
        second.request("GET", parsed.path, headers=HEADERS)
        response = second.getresponse()
        response.read()
        return response.status
    finally:
        second.close()


def summarized_records(lab: LoopbackLab) -> list[dict[str, object]]:
    return [
        {
            "origin": item["origin"],
            "path": item["path"],
            "authorization_present": item["authorization"] is not None,
            "cookie_present": item["cookie"] is not None,
            "authorization_matches_synthetic_input": item["authorization"] == AUTH,
            "cookie_matches_synthetic_input": item["cookie"] == COOKIE,
        }
        for item in lab.snapshot()
    ]


def run() -> dict[str, object]:
    with LoopbackLab() as lab:
        input_record = {
            "initial_url": lab.a_url + "/cross",
            "method": "GET",
            "authorization_sha256": hashlib.sha256(AUTH.encode()).hexdigest(),
            "cookie_sha256": hashlib.sha256(COOKIE.encode()).hexdigest(),
            "credential_values": "synthetic local-only markers, omitted from this receipt",
            "origins": {"A": lab.a_url, "B": lab.b_url},
        }

        weak_status = weak_loopback_follow(lab)
        weak_records = summarized_records(lab)
        lab.clear()

        fixed = RedirectClient().get(input_record["initial_url"], headers=HEADERS)
        fixed_records = summarized_records(lab)
        fixed_hops = [
            {
                "from_origin": hop.from_origin,
                "to_origin": hop.to_origin,
                "status": hop.status,
                "stripped_header_names": list(hop.stripped_header_names),
            }
            for hop in fixed.history
        ]
        lab.clear()

        same = RedirectClient().get(lab.a_url + "/relative", headers=HEADERS)
        same_records = summarized_records(lab)
        lab.clear()

        mixed = RedirectClient().get(
            f"http://localhost:{lab.a_port}/mixed", headers=HEADERS
        )
        mixed_records = summarized_records(lab)
        lab.clear()

        try:
            RedirectClient().get(lab.a_url + "/loop", headers=HEADERS)
            loop_result = "unexpected success"
        except RedirectLoopError:
            loop_result = "RedirectLoopError"
        lab.clear()

        try:
            RedirectClient(max_redirects=2).get(lab.a_url + "/count/0", headers=HEADERS)
            limit_result = "unexpected success"
        except RedirectLimitError:
            limit_result = "RedirectLimitError"
        limit_records = summarized_records(lab)

    baseline_leaked = (
        len(weak_records) == 2
        and weak_records[1]["origin"] == "B"
        and weak_records[1]["authorization_matches_synthetic_input"]
        and weak_records[1]["cookie_matches_synthetic_input"]
    )
    fixed_protected = (
        len(fixed_records) == 2
        and fixed_records[0]["authorization_matches_synthetic_input"]
        and fixed_records[0]["cookie_matches_synthetic_input"]
        and fixed_records[1]["origin"] == "B"
        and not fixed_records[1]["authorization_present"]
        and not fixed_records[1]["cookie_present"]
    )
    same_preserved = (
        len(same_records) == 2
        and all(item["origin"] == "A" for item in same_records)
        and same_records[1]["authorization_matches_synthetic_input"]
        and same_records[1]["cookie_matches_synthetic_input"]
    )
    mixed_preserved = (
        len(mixed_records) == 2
        and mixed_records[1]["origin"] == "A"
        and mixed_records[1]["authorization_matches_synthetic_input"]
    )
    bounded = loop_result == "RedirectLoopError" and limit_result == "RedirectLimitError" and len(limit_records) == 3
    checks = {
        "weak_baseline_leaks_only_synthetic_credentials": baseline_leaked,
        "fixed_cross_origin_strips_credentials": fixed_protected,
        "relative_same_origin_preserves_credentials": same_preserved,
        "mixed_case_same_origin_preserves_credentials": mixed_preserved,
        "loop_and_hop_limit_bounded": bounded,
    }
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "version": "0.1.2",
        "environment": "two ThreadingHTTPServer instances bound to 127.0.0.1 on ephemeral ports",
        "input": input_record,
        "weak_baseline": {"status": weak_status, "server_receipts": weak_records},
        "fixed_client": {"status": fixed.status, "final_url": fixed.url, "hops": fixed_hops, "server_receipts": fixed_records},
        "same_origin_relative": {"status": same.status, "server_receipts": same_records},
        "same_origin_mixed_case": {"status": mixed.status, "server_receipts": mixed_records},
        "redirect_bounds": {"loop": loop_result, "limit": limit_result, "limit_server_receipts": limit_records},
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: run_local_experiment.py OUTPUT_JSON")
    output = Path(sys.argv[1]).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    receipt = run()
    output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(receipt["result"], output)
    raise SystemExit(0 if receipt["result"] == "PASS" else 1)
