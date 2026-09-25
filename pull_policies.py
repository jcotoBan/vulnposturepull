#!/usr/bin/env python3
"""
Pull Sysdig Secure policy configurations to CSV:
  1. vulnerability_policies_report.csv  — VM policies with stages & bundle rules
  2. posture_policies_report.csv        — Enabled posture policies (metadata)
  3. posture_controls_report.csv        — Customer-created (non-system) posture controls
  4. report_schedules_report.csv        — Configured report schedules
  5. kspm_migration_report.csv          — KSPM vs old benchmark runner per cluster

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


# ── Report Schedules ─────────────────────────────────────────────────────────


def _schedule_row(source, schedule_id, name, description, enabled, status,
                  report_name, report_format, compression, schedule_cron,
                  timezone, time_frame, zones, policies, notification_channels,
                  entity_type, filters, created_by, created_on, modified_on,
                  last_scheduled_on, last_completed_on):
    return {
        "source": source,
        "schedule_id": schedule_id,
        "name": name,
        "description": description,
        "enabled": enabled,
        "status": status,
        "report_name": report_name,
        "report_format": report_format,
        "compression": compression,
        "schedule_cron": schedule_cron,
        "timezone": timezone,
        "time_frame": time_frame,
        "zones": zones,
        "policies": policies,
        "notification_channels": notification_channels,
        "entity_type": entity_type,
        "filters": filters,
        "created_by": created_by,
        "created_on": created_on,
        "modified_on": modified_on,
        "last_scheduled_on": last_scheduled_on,
        "last_completed_on": last_completed_on,
    }


def fetch_report_schedules():
    """Return all configured report schedules from both platform and legacy APIs."""
    rows = []

    # ── Platform (current) reporting ─────────────────────────────────────────
    print("  Fetching platform report schedules...")
    for s in api_get("/api/platform/reporting/v1/schedules"):
        rows.append(_schedule_row(
            source="platform",
            schedule_id=s.get("id", ""),
            name=s.get("name", ""),
            description=s.get("description", ""),
            enabled=s.get("enabled", ""),
            status=s.get("status", ""),
            report_name=s.get("reportName", ""),
            report_format=s.get("reportFormat", ""),
            compression=s.get("compression", ""),
            schedule_cron=s.get("schedule", ""),
            timezone=s.get("timezone", ""),
            time_frame=s.get("timeFrame", ""),
            zones="; ".join(str(z) for z in s.get("zones") or []),
            policies="; ".join(str(p) for p in s.get("policies") or []),
            notification_channels="; ".join(
                f"{ch.get('type')}({ch.get('id')})"
                for ch in s.get("notificationChannels") or []
            ),
            entity_type="",
            filters="",
            created_by=s.get("createdBy", ""),
            created_on=s.get("createdOn", ""),
            modified_on=s.get("modifiedOn", ""),
            last_scheduled_on=s.get("lastScheduledOn", ""),
            last_completed_on=s.get("lastCompletedOn", ""),
        ))

    # ── Legacy scanning reporting ─────────────────────────────────────────────
    print("  Fetching legacy scanning report schedules...")
    try:
        legacy_schedules = api_get("/api/scanning/reporting/v2/schedules")
    except requests.HTTPError as e:
        print(f"  Warning: legacy scanning reporting unavailable ({e}) — skipping.")
        legacy_schedules = []

    for s in legacy_schedules:
        # Flatten filters into a readable string
        condition_filters = s.get("filters", {}).get("conditionFilters", {})
        scope_filter = s.get("filters", {}).get("scopeFilter", "")
        filter_parts = [
            f"{k}={','.join(v.get('value', []))}"
            for k, v in condition_filters.items()
            if v.get("value")
        ]
        if scope_filter:
            filter_parts.append(f"scope={scope_filter}")
        filters_str = "; ".join(filter_parts)

        rows.append(_schedule_row(
            source="legacy (scanning)",
            schedule_id=s.get("id", ""),
            name=s.get("name", ""),
            description=s.get("description", ""),
            enabled=s.get("enabled", ""),
            status="",
            report_name=s.get("reportType", ""),
            report_format=s.get("reportFormat", ""),
            compression=s.get("compression", ""),
            schedule_cron=s.get("schedule", ""),
            timezone="",
            time_frame="",
            zones="",
            policies="",
            notification_channels="",
            entity_type=s.get("entityType", ""),
            filters=filters_str,
            created_by="",
            created_on=s.get("createdAt", ""),
            modified_on="",
            last_scheduled_on=s.get("reportLastScheduledAt", ""),
            last_completed_on=s.get("reportLastCompletedAt", ""),
        ))

    return rows


# ── KSPM Migration Check ─────────────────────────────────────────────────────

_NEW_PATTERN = r"(?i).*(kspm-analyzer|sysdig-shield).*"
_OLD_PATTERN = r"(?i).*(node-analyzer|bench-runner|node-benchmark-runner).*"


def _run_sysql(query):
    resp = SESSION.post(
        f"{BASE_URL}/api/sysql/v1/query",
        json={"query": query},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json().get("items", [])


class SysQLUnavailable(Exception):
    pass


def _fetch_kspm_components(pattern, label):
    print(f"  Querying for {label} components...")
    query = (
        f"MATCH KubeWorkload "
        f"WHERE KubeWorkload.name =~ '{pattern}' "
        f"RETURN DISTINCT KubeWorkload.clusterName, KubeWorkload.name, "
        f"KubeWorkload.type, KubeWorkload.namespaceName;"
    )
    try:
        items = _run_sysql(query)
    except requests.HTTPError as e:
        raise SysQLUnavailable(e) from e
    print(f"    Found {len(items)} workload(s)")
    return items


def fetch_kspm_migration():
    """Classify each cluster as new_only, old_only, or migrating."""
    try:
        new_items = _fetch_kspm_components(_NEW_PATTERN, "new (kspm-analyzer / sysdig-shield)")
        old_items = _fetch_kspm_components(_OLD_PATTERN, "old (node-analyzer / bench-runner)")
    except SysQLUnavailable as e:
        print(f"  Warning: SysQL API unavailable ({e}) — skipping KSPM migration check.")
        return []

    new_clusters = {i.get("KubeWorkload.clusterName"): i for i in new_items}
    old_clusters = {i.get("KubeWorkload.clusterName"): i for i in old_items}
    all_clusters = sorted(set(new_clusters) | set(old_clusters))

    rows = []
    for cluster in all_clusters:
        has_new = cluster in new_clusters
        has_old = cluster in old_clusters
        status = "migrating" if (has_new and has_old) else ("new_only" if has_new else "old_only")
        rows.append({
            "cluster": cluster,
            "status": status,
            "new_components": "; ".join(
                i["KubeWorkload.name"] for i in new_items
                if i.get("KubeWorkload.clusterName") == cluster
            ),
            "old_components": "; ".join(
                i["KubeWorkload.name"] for i in old_items
                if i.get("KubeWorkload.clusterName") == cluster
            ),
        })

    for status in ("old_only", "migrating", "new_only"):
        matches = [r["cluster"] for r in rows if r["status"] == status]
        if matches:
            print(f"  {status}: {', '.join(matches)}")

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

    print("\n=== Report Schedules ===")
    schedule_rows = fetch_report_schedules()
    write_csv(
        "report_schedules_report.csv",
        schedule_rows,
        [
            "source", "schedule_id", "name", "description", "enabled", "status",
            "report_name", "report_format", "compression",
            "schedule_cron", "timezone", "time_frame",
            "zones", "policies", "notification_channels",
            "entity_type", "filters",
            "created_by", "created_on", "modified_on",
            "last_scheduled_on", "last_completed_on",
        ],
    )

    print("\n=== KSPM Migration Check ===")
    kspm_rows = fetch_kspm_migration()
    if kspm_rows:
        write_csv(
            "kspm_migration_report.csv",
            kspm_rows,
            ["cluster", "status", "new_components", "old_components"],
        )

    print("\nDone.")


if __name__ == "__main__":
    main()
