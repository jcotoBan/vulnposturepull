# Sysdig Policy Configuration Exporter

Exports your Sysdig Secure policy configurations to CSV files for auditing, reporting, or onboarding reviews.

## What it exports

| File | Contents |
|---|---|
| `vulnerability_policies_report.csv` | All VM policies with their active stages, rule bundles, and predicate conditions |
| `posture_policies_report.csv` | All enabled posture/compliance policies with metadata |
| `posture_controls_report.csv` | Customer-created (non-system) posture controls |
| `report_schedules_report.csv` | All configured report schedules (platform and legacy scanning) |
| `kspm_migration_report.csv` | KSPM migration status per cluster (new KSPM vs old benchmark runner) |

### Vulnerability policies CSV columns

| Column | Description |
|---|---|
| `policy_name` | Policy display name |
| `policy_id` | Numeric policy ID |
| `policy_description` | Policy description |
| `active_stages` | Stages where the policy is enforced (`pipeline`, `registry`, `runtime`, `admission_control`) |
| `stages_config` | Per-stage configuration (behaviour, unknownImageAction, scope) |
| `bundle_id` | Rule bundle ID |
| `bundle_name` | Rule bundle name |
| `bundle_type` | `predefined` (Sysdig-managed) or `custom` (customer-created) |
| `bundle_description` | Rule bundle description |
| `rule_id` | Individual rule ID within the bundle |
| `rule_type` | Rule category (e.g. `vulnSeverityAndThreats`, `vulnDenyList`) |
| `rule_predicates` | Human-readable conditions joined with `AND` (e.g. `vulnSeverityEquals(level=critical) AND vulnIsFixable`) |

> Each row represents one rule. A policy with multiple bundles or multiple rules per bundle will produce multiple rows.

---

## Setup

**Requirements:** Python 3.8+

```bash
cd pull_policies_script
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

### Option 1 — pass arguments directly

```bash
python3 pull_policies.py \
  --url https://app.us4.sysdig.com \
  --token <your-api-token>
```

### Option 2 — use environment variables

```bash
export SYSDIG_SECURE_URL="https://app.us4.sysdig.com"
export SYSDIG_SECURE_API_TOKEN="your-api-token"
python3 pull_policies.py
```

Arguments take precedence over environment variables when both are set.

---

## Supported regions

| Region | URL |
|---|---|
| US East (us1) | `https://secure.sysdig.com` |
| US West — Oregon (us2) | `https://us2.app.sysdig.com` |
| US West — GCP (us3) | `https://app.us3.sysdig.com` |
| US West — GCP Dallas (us4) | `https://app.us4.sysdig.com` |
| EU Central — Frankfurt (eu1) | `https://eu1.app.sysdig.com` |
| EU North — Stockholm (eu2) | `https://app.eu2.sysdig.com` |
| AP Sydney (au1) | `https://app.au1.sysdig.com` |
| AP Mumbai (in1) | `https://app.in1.sysdig.com` |
| AP Tokyo (jp1) | `https://app.jp1.sysdig.com` |
| On-premises | Your Sysdig installation URL |

---

## Required API token permissions

The token needs read access to:
- Vulnerability Management policies and bundles
- Posture policies and controls (`cspm.policies.read`)
- Report schedules
- SysQL query execution (for KSPM migration check)

---

## Report schedules CSV columns

| Column | Description |
|---|---|
| `source` | `platform` (current API) or `legacy (scanning)` |
| `schedule_id` | Schedule ID |
| `name` | Schedule name |
| `enabled` | Whether the schedule is active |
| `status` | Schedule status (platform only) |
| `report_name` | Report type being generated |
| `report_format` | Output format (csv, pdf, ndjson) |
| `schedule_cron` | Cron expression for the schedule |
| `timezone` | Timezone for the schedule (platform only) |
| `zones` / `policies` | Zones and policies scoped to this schedule (platform only) |
| `notification_channels` | Delivery channels (platform only) |
| `entity_type` / `filters` | Scope filters (legacy only) |

---

## KSPM migration CSV columns

| Column | Description |
|---|---|
| `cluster` | Kubernetes cluster name |
| `status` | `new_only` — KSPM or sysdig-shield detected; `old_only` — node-analyzer/bench-runner only; `migrating` — both found |
| `new_components` | Workload names matching the new KSPM stack |
| `old_components` | Workload names matching the old benchmark runner stack |

> This section requires the SysQL API. On on-premises installs where SysQL is unavailable, a warning is printed and `kspm_migration_report.csv` is not written.

---

## Notes

- **Posture controls per policy** — the Sysdig CSPM API does not expose the policy→requirements→controls mapping through any public endpoint. Controls are exported as a separate file. If no customer-created controls exist, `posture_controls_report.csv` is not written.
- **Pagination** — all sections paginate fully regardless of data volume. VM policies use cursor-based pagination; posture endpoints page until an empty response is returned.
- **On-premises compatibility** — the legacy scanning schedules endpoint and the SysQL API may not be available on all on-premises versions. Both sections fail gracefully with a warning if the endpoint returns an error.
