#!/usr/bin/env python3
"""
Pull Sysdig Secure policy configurations to CSV:
  1. vulnerability_policies_report.csv  — VM policies with stages & bundle rules
  2. posture_policies_report.csv        — Enabled posture policies (metadata)
  3. posture_controls_report.csv        — Customer-created (non-system) posture controls

Usage:
    python3 pull_policies.py --url https://app.us4.sysdig.com --token <api-token>

    # Or via environment variables:
    export SYSDIG_SECURE_URL="https://app.us4.sysdig.com"
    export SYSDIG_SECURE_API_TOKEN="your-token"
    python3 pull_policies.py

Note on posture controls per policy:
    The Sysdig CSPM API does not expose the policy→requirements→controls tree
    through any documented REST endpoint. Controls are therefore exported as a
    separate file rather than nested under each policy row.
"""

import argparse
import csv
import os
import sys

import requests

# Initialised in main() after argument parsing
SESSION: requests.Session = None
BASE_URL: str = ""


def api_get(path, params=None):
    resp = SESSION.get(f"{BASE_URL}{path}", params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


# ── Vulnerability Management Policies ────────────────────────────────────────


def _predicate_summary(predicate):
    ptype = predicate.get("type", "")
    extra = predicate.get("extra") or {}
    if not extra:
        return ptype
    parts = ", ".join(f"{k}={v}" for k, v in extra.items())
    return f"{ptype}({parts})"


def _stage_summary(stages):
    parts = []
    for stage in stages:
        name = stage.get("name", "")
        cfgs = stage.get("configuration", [{}])
        cfg = cfgs[0] if cfgs else {}
        details = []
        if cfg.get("behaviour"):
            details.append(f"behaviour={cfg['behaviour']}")
        if cfg.get("unknownImageAction"):
            details.append(f"unknownImageAction={cfg['unknownImageAction']}")
        if cfg.get("scope"):
            details.append(f"scope={cfg['scope']}")
        parts.append(f"{name}({', '.join(details)})" if details else name)
    return "; ".join(parts)


def _all_vuln_policies():
    """Page through all VM policies using cursor-based pagination."""
    cursor = None
    while True:
        params = {"limit": 100}
        if cursor:
            params["cursor"] = cursor
        data = api_get("/secure/vulnerability/v1/policies", params=params)
        batch = data.get("data", [])
        yield from batch
        cursor = data.get("page", {}).get("next")
        if not cursor or not batch:
            break


def fetch_vuln_policies():
    """Return one row per policy × bundle rule."""
    print("  Listing VM policies...")
    rows = []

    for p in _all_vuln_policies():
        print(f"    Fetching detail for: {p['name']}")
        detail = api_get(f"/secure/vulnerability/v1/policies/{p['id']}")
        if isinstance(detail, list):
            detail = detail[0]

        stages = detail.get("stages", [])
        stage_names = "; ".join(s.get("name", "") for s in stages)
        stages_summary = _stage_summary(stages)

        bundles = detail.get("bundles", [])
        if not bundles:
            rows.append({
                "policy_name": detail["name"],
                "policy_id": detail["id"],
                "policy_description": detail.get("description", ""),
                "active_stages": stage_names,
                "stages_config": stages_summary,
                "bundle_id": "", "bundle_name": "", "bundle_type": "",
                "bundle_description": "", "rule_id": "", "rule_type": "",
                "rule_predicates": "",
            })
            continue

        for bundle_ref in bundles:
            bundle_id = bundle_ref.get("id")
            print(f"      Fetching bundle: {bundle_ref.get('name')}")
            bundle = api_get(f"/secure/vulnerability/v1/bundles/{bundle_id}")

            rules = bundle.get("rules", [])
            if not rules:
                rows.append({
                    "policy_name": detail["name"],
                    "policy_id": detail["id"],
                    "policy_description": detail.get("description", ""),
                    "active_stages": stage_names,
                    "stages_config": stages_summary,
                    "bundle_id": bundle["id"],
                    "bundle_name": bundle["name"],
                    "bundle_type": bundle.get("bundleType", ""),
                    "bundle_description": bundle.get("description", ""),
                    "rule_id": "", "rule_type": "", "rule_predicates": "",
                })
                continue

            for rule in rules:
                predicate_summary = " AND ".join(
                    _predicate_summary(pred) for pred in rule.get("predicates", [])
                )
                rows.append({
                    "policy_name": detail["name"],
                    "policy_id": detail["id"],
                    "policy_description": detail.get("description", ""),
                    "active_stages": stage_names,
                    "stages_config": stages_summary,
                    "bundle_id": bundle["id"],
                    "bundle_name": bundle["name"],
                    "bundle_type": bundle.get("bundleType", ""),
                    "bundle_description": bundle.get("description", ""),
                    "rule_id": rule.get("ruleId", ""),
                    "rule_type": rule.get("ruleType", ""),
                    "rule_predicates": predicate_summary,
                })

    return rows


# ── Posture Policies ──────────────────────────────────────────────────────────

TYPE_LABELS = {0: "compliance", 1: "cloud", 2: "custom"}
KIND_LABELS = {0: "unknown", 1: "framework", 2: "control"}


def fetch_posture_policies():
    """Return all active posture policies, paginating until the last page."""
    print("  Fetching posture policies...")
    page, page_size = 0, 100
    rows = []

    while True:
        data = api_get(
            "/api/cspm/v1/policy/policies/list",
            params={"pageNumber": page, "pageSize": page_size},
        )
        batch = data.get("data", [])
        if not batch:
            break

        for p in batch:
            if not p.get("isActive", False):
                continue
            rows.append({
                "policy_name": p.get("name", ""),
                "policy_id": p.get("id", ""),
                "description": p.get("description", "")[:300].replace("\n", " "),
                "is_active": p.get("isActive", ""),
                "is_custom": not p.get("isSystem", True),
                "version": p.get("version", ""),
                "apl_version": p.get("aplVersion", ""),
                "platform": p.get("platform", ""),
                "type": TYPE_LABELS.get(p.get("type"), p.get("type", "")),
                "kind": KIND_LABELS.get(p.get("kind"), p.get("kind", "")),
                "authors": p.get("authors", ""),
            })

        # A page smaller than page_size means we've reached the last page
        if len(batch) < page_size:
            break
        page += 1

    return rows


# ── Posture Controls (customer-created) ──────────────────────────────────────


def fetch_posture_controls():
    """
    Walk all pages of posture controls, collecting customer-created ones
    (isSystem=False). The server applies no server-side isCustom filter,
    so we filter client-side and walk until an empty page is returned.
    """
    print("  Fetching posture controls (custom only)...")
    page, page_size = 0, 200
    rows = []

    while True:
        data = api_get(
            "/api/cspm/v1/policy/controls/search",
            params={"pageNumber": page, "pageSize": page_size},
        )
        batch = data.get("data", [])
        if not batch:
            break

        for c in batch:
            if c.get("isSystem", True):
                continue
            rows.append({
                "control_id": c.get("id", ""),
                "control_name": c.get("name", ""),
                "description": c.get("description", "")[:300].replace("\n", " "),
                "severity": c.get("severity", ""),
                "resource_kind": c.get("resourceKind", ""),
                "resource_kind_display": c.get("resourceKindDisplayName", ""),
                "platform": c.get("platform", ""),
                "version": c.get("version", ""),
                "is_manual": c.get("isManual", ""),
                "attribute_id": c.get("attributeId", ""),
            })

        if len(batch) < page_size:
            break
        page += 1

    return rows


# ── CSV Writer ────────────────────────────────────────────────────────────────


def write_csv(filename, rows, fieldnames):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  -> {filename} ({len(rows)} rows)")


# ── Argument parsing ──────────────────────────────────────────────────────────


def parse_args():
    parser = argparse.ArgumentParser(
        description="Pull Sysdig Secure VM and posture policy configurations to CSV."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("SYSDIG_SECURE_URL", ""),
        help="Sysdig Secure base URL (e.g. https://app.us4.sysdig.com). "
             "Defaults to $SYSDIG_SECURE_URL.",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SYSDIG_SECURE_API_TOKEN", ""),
        help="Sysdig Secure API token. Defaults to $SYSDIG_SECURE_API_TOKEN.",
    )
    return parser.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    global SESSION, BASE_URL

    args = parse_args()

    if not args.url or not args.token:
        print(
            "Error: --url and --token are required (or set SYSDIG_SECURE_URL / "
            "SYSDIG_SECURE_API_TOKEN).",
            file=sys.stderr,
        )
        sys.exit(1)

    BASE_URL = args.url.rstrip("/")
    SESSION = requests.Session()
    SESSION.headers.update({"Authorization": f"Bearer {args.token}"})

    print("=== Vulnerability Management Policies ===")
    vuln_rows = fetch_vuln_policies()
    write_csv(
        "vulnerability_policies_report.csv",
        vuln_rows,
        [
            "policy_name", "policy_id", "policy_description",
            "active_stages", "stages_config",
            "bundle_id", "bundle_name", "bundle_type", "bundle_description",
            "rule_id", "rule_type", "rule_predicates",
        ],
    )

    print("\n=== Posture Policies (enabled) ===")
    posture_rows = fetch_posture_policies()
    write_csv(
        "posture_policies_report.csv",
        posture_rows,
        [
            "policy_name", "policy_id", "description",
            "is_active", "is_custom", "type", "kind",
            "version", "apl_version", "platform", "authors",
        ],
    )

    print("\n=== Posture Controls (customer-created) ===")
    control_rows = fetch_posture_controls()
    if control_rows:
        write_csv(
            "posture_controls_report.csv",
            control_rows,
            [
                "control_id", "control_name", "description",
                "severity", "resource_kind", "resource_kind_display",
                "platform", "version", "is_manual", "attribute_id",
            ],
        )
    else:
        print("  No customer-created controls found.")

    print("\nDone.")


if __name__ == "__main__":
    main()
