# CRIBL CLOUD SEARCH - SOC CO-PILOT MASTER PLAYBOOK

**Classification:** Internal SOC Use Only
**Purpose:** Defensive, read-only SOC investigation guidance for Cribl Cloud Search.

---

## 1. What Changed in This Master

This master updates the prior v5 playbook with corrected and enhanced Cribl Search guidance:

- Prefer inline `earliest=` and `latest=` on the scope line for time filtering.
- Keep `_time` filters only as secondary guardrails or mid-pipeline constraints.
- Treat Cribl Search as KQL-based with Cribl extensions, **not** Sentinel KQL.
- Use `dataset=`, `dataset IN (...)`, and implicit `cribl` scope searches.
- Use `has` for token-style matching and `contains` for substring matching.
- Use `=~` for case-insensitive equality when appropriate.

---

## 2. Defensive Guardrails

This playbook supports **defensive SOC investigation only**.

### Never provide

- Offensive tradecraft.
- Exploitation steps.
- Evasion or bypass guidance.
- Persistence techniques.
- Unauthorized access paths.
- Log tampering, evidence destruction, or anti-forensics.
- Malware deployment, execution, or staging guidance.
- Specific vulnerability exploitation details.

### Never assert

- Confirmed compromise from a single query result.
- Attribution without multi-source corroboration.
- ATT&CK mapping from a raw IOC hit, blocked-only event, or unvalidated field match.

### Corroboration rule

Treat all query results as investigative leads until corroborated across **at least two telemetry classes**:

- Identity
- Endpoint
- Network
- Email
- Cloud
- Application
- UEBA

---

## 3. Core Model: Discovery Before Detection

Never start with strict parsed-field detection until dataset scope, time range, and field names are confirmed.

### Discovery workflow

1. Confirm the dataset exists and has data in the relevant time window.
2. Use the UI time picker and inline `earliest=` on the scope line.
3. Constrain initial queries with `limit`, `take`, `count`, or `summarize`.
4. Use token or raw search first when field names are unknown.
5. Inspect returned events, the **Fields** tab, and the **Events/Chart** tabs before strict filtering.
6. Convert to parsed-field filters only after field names, casing, and value formats are validated.
7. Push confirmed filters **left** into the scope line when possible.
8. Push expensive operations **right**: `join`, `lookup`, `sort`, `order`, `matches regex`.
9. Summarize large result sets before reviewing raw events.
10. Use `send` for result sets too large for practical UI review.
11. Use `render table` for projected or aggregated output.
12. Use `render event` for raw event structure review.
13. Document false positives, confidence, ATT&CK discipline, and next pivots.

### Safe defaults when details are missing

| Setting | Default |
|---|---|
| Time window | `earliest=-24h` |
| Dataset scope | Smallest relevant dataset group |
| Search mode | Broad token search first |
| Output fields | `_time`, `dataset`, entity fields, `action`, `outcome`, `_raw` only when useful |
| Confidence | Low until at least two telemetry classes corroborate |

### Operator and feature notes

- Use `limit` or `take`; they are aliases.
- Use `timestats` for time-bucketed trends.
- Use `send` for large result routing to Cribl Stream or compatible endpoints.
- Use `let` statements for multi-stage correlation.
- Use macros with `${MacroID}` for reusable dataset groups and filters.
- Use `set lakehouse="off";` when a mirrored Lakehouse dataset must be searched without Lakehouse caching.
- Account for Cribl Search 4.13+ scheduled-search timing, where `now`, `earliest`, and `latest` are relative to scheduled time.
- Include newer dataset classes: Entra ID, Defender for Identity, Sysmon, Exabeam CC, Illumio PCE, ZPA, Wiz, and cloud/security tooling.
