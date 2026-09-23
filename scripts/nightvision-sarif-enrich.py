#!/usr/bin/env python3
"""Make a NightVision SARIF export read well in GitHub Code Scanning.

`nightvision export sarif` produces valid SARIF, but GitHub renders it poorly:
every rule's help panel is boilerplate, result messages are Markdown (GitHub
shows result messages as plain text, so the reader sees raw ** and emoji), all
findings are "warning" or "note" so SQL injection looks like a missing header,
and findings NightVision could not trace to source point at a file named "/".

This script rewrites the export in place for GitHub:
  * rule help, CWE tags, precision and security-severity per rule
  * a plain-text message per result: "<finding> on <METHOD> <path>", the
    description, and the NightVision evidence link
  * level from NightVision risk (critical/high -> error, medium -> warning)
  * untraced findings moved to a real file, and dropped when the same rule
    already has a source-mapped result
  * informational results dropped (they stay in the raw export)
It also writes a Markdown job summary when GITHUB_STEP_SUMMARY is set.

Standard library only, so it runs on any GitHub-hosted runner.
"""

import argparse
import json
import os
import re
import sys

RISK_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
RISK_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}
RISK_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}
CONFIDENCE_PRECISION = {"Certain": "very-high", "High": "high", "Medium": "medium", "Low": "low"}
PRECISION_ORDER = ["low", "medium", "high", "very-high"]

# First match wins. Keyed on the NightVision check name.
CWE_BY_NAME = [
    (r"sql injection", 89),
    (r"spring4shell", 94),
    (r"cross site scripting|xss", 79),
    (r"reflected unencoded", 116),
    (r"httponly", 1004),
    (r"without secure flag", 614),
    (r"samesite", 1275),
    (r"error disclosure|stack trace", 209),
    (r"header|policy", 693),
]

# Used when the export carries no description for a finding (it omits one for some
# of the most serious checks). Keyed on CWE.
FALLBACK_HELP = {
    89: (
        "## Summary\n\nNightVision sent SQL injection payloads to this endpoint and the database "
        "responses proved the input reaches a SQL query unescaped. An attacker can read or change "
        "any data the application's database user can reach.\n\n"
        "## Solution\n\nBuild queries with parameters (`PreparedStatement`, JPA named parameters, "
        "Spring Data query methods) instead of concatenating request input into SQL strings.\n\n"
        "## References\n- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    ),
    94: (
        "## Summary\n\nThe endpoint accepted a Spring4Shell (CVE-2022-22965) data-binding payload. "
        "Spring Framework data binding on affected versions lets a request set `class.module.classLoader` "
        "properties, which leads to remote code execution on Tomcat deployments.\n\n"
        "## Solution\n\nUpgrade Spring Framework to 5.3.18+ or 5.2.20+ (Spring Boot 2.6.6+ or 2.5.12+). "
        "Until then, restrict bindable fields with `@InitBinder` / `setDisallowedFields`.\n\n"
        "## References\n- https://spring.io/security/cve-2022-22965\n- https://nvd.nist.gov/vuln/detail/CVE-2022-22965"
    ),
}

NV_LINK = re.compile(r"https://app\.nightvision\.net/\S+")
ENDPOINT = re.compile(r"The `(?P<path>[^`]+)` URL path is vulnerable to \*\*.+?\*\* via a `(?P<method>[A-Z]+)` request")
BACKTICK_HEADER = re.compile(r"`([A-Z][A-Za-z]+(?:-[A-Z][A-Za-z]+)+)`")


def risk_of(result):
    risk = str(result.get("properties", {}).get("nightvision-risk", "")).upper()
    return risk if risk in RISK_ORDER else "LOW"


def to_plain(markdown):
    text = re.sub(r"```(.*?)```", r"\1", markdown, flags=re.S)
    text = re.sub(r"^#+\s*", "", text, flags=re.M)
    text = text.replace("**", "").replace("`", "")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def parse_message(markdown):
    """Split NightVision's Markdown message into endpoint, description and link."""
    link = NV_LINK.search(markdown)
    endpoint = ENDPOINT.search(markdown)
    description = markdown.split("**Description**:", 1)[1] if "**Description**:" in markdown else ""
    description = NV_LINK.sub("", description)
    description = re.sub(r"🔍.*$", "", description, flags=re.S).strip()
    return {
        "link": link.group(0).rstrip(").") if link else None,
        "method": endpoint.group("method") if endpoint else None,
        "path": endpoint.group("path") if endpoint else None,
        "description": description,
    }


def display_name(rule_name, description):
    # Generic Nuclei buckets say nothing on their own; name the header they are about.
    if rule_name.startswith("Uncategorized Nuclei Finding"):
        header = BACKTICK_HEADER.search(description)
        if header:
            return f"Missing {header.group(1)} header"
    return rule_name


def cwe_for(name):
    lowered = name.lower()
    for pattern, cwe in CWE_BY_NAME:
        if re.search(pattern, lowered):
            return cwe
    return None


def strip_placeholders(node):
    """Drop SARIF placeholder values (-1 indexes, empty arrays/objects) the exporter emits."""
    if isinstance(node, dict):
        cleaned = {}
        for key, value in node.items():
            value = strip_placeholders(value)
            if value == -1 or value in ([], {}):
                continue
            cleaned[key] = value
        return cleaned
    if isinstance(node, list):
        return [strip_placeholders(item) for item in node]
    return node


def location_uri(result):
    locations = result.get("locations") or [{}]
    return locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")


def is_traced(result):
    uri = location_uri(result)
    return bool(uri) and uri != "/" and os.path.isfile(uri)


def enrich(sarif, min_risk, fallback_uri):
    kept_findings = []
    dropped = 0
    for run in sarif.get("runs", []):
        driver = run["tool"]["driver"]
        rules = {rule["id"]: rule for rule in driver.get("rules", [])}
        traced_rules = {r["ruleId"] for r in run.get("results", []) if is_traced(r)}
        rule_names_by_file = {}
        for r in run.get("results", []):
            rule_names_by_file.setdefault(location_uri(r), []).append(rules.get(r["ruleId"], {}).get("name", ""))
        untraced_seen = set()

        results = []
        for result in run.get("results", []):
            risk = risk_of(result)
            rule = rules.get(result["ruleId"], {"id": result["ruleId"], "name": result["ruleId"]})
            rule_name = rule.get("name") or rule.get("shortDescription", {}).get("text", result["ruleId"])
            parsed = parse_message(result.get("message", {}).get("text", ""))
            name = display_name(rule_name, parsed["description"])

            if RISK_ORDER.index(risk) < RISK_ORDER.index(min_risk):
                dropped += 1
                continue
            if not is_traced(result):
                # Untraced duplicates: the same rule is already mapped to source, or already
                # reported once at the fallback location.
                if result["ruleId"] in traced_rules or result["ruleId"] in untraced_seen:
                    dropped += 1
                    continue
                untraced_seen.add(result["ruleId"])
            if name != rule_name:
                # A generic Nuclei bucket that repeats a named header check at the same place.
                header = name.split(" ")[1]
                if any(header in other for other in rule_names_by_file.get(location_uri(result), []) if other != rule_name):
                    dropped += 1
                    continue
            where = f"{parsed['method']} {parsed['path']}" if parsed["path"] else "the application"

            lines = [f"{name} on {where}."]
            if parsed["description"]:
                lines += ["", to_plain(parsed["description"])[:1800]]
            if parsed["link"]:
                lines += ["", f"Proof (request, response, payload) in NightVision: {parsed['link']}"]
            result["message"] = {"text": "\n".join(lines)}
            result["level"] = RISK_LEVEL[risk]
            result.setdefault("properties", {})["security-severity"] = RISK_SCORE[risk]

            if not is_traced(result):
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": fallback_uri},
                        "region": {"startLine": 1},
                    },
                    "message": {"text": "Application-wide finding; NightVision did not trace it to a single handler."},
                }]
            else:
                region = result["locations"][0]["physicalLocation"].setdefault("region", {})
                region["message"] = {"text": f"Handler for {where}"}

            # The issue id is regenerated per scan; matching on it would reopen alerts every run.
            result.get("partialFingerprints", {}).pop("nightvisionIssueID/v1", None)

            update_rule(rule, rule_name, parsed, risk, result.get("properties", {}))
            results.append(result)
            kept_findings.append({
                "risk": risk,
                "name": name,
                "where": where,
                "file": location_uri(result),
                "line": result["locations"][0]["physicalLocation"].get("region", {}).get("startLine"),
                "link": parsed["link"],
            })

        run["results"] = results
        used = {r["ruleId"] for r in results}
        driver["rules"] = [rule for rule in driver.get("rules", []) if rule["id"] in used]
        driver.update({
            "fullName": "NightVision DAST",
            "organization": "NightVision",
            "informationUri": "https://docs.nightviz.ai",
        })
        # The exporter lists the NightVision web UI as an "artifact"; it is not a file in the repo.
        run.pop("artifacts", None)

    return strip_placeholders(sarif), kept_findings, dropped


def update_rule(rule, rule_name, parsed, risk, result_properties):
    props = rule.setdefault("properties", {})
    worst = props.get("_nv_risk")
    if worst is None or RISK_ORDER.index(risk) > RISK_ORDER.index(worst):
        props["_nv_risk"] = risk
        props["security-severity"] = RISK_SCORE[risk]
        props["problem.severity"] = {"error": "error", "warning": "warning", "note": "recommendation"}[RISK_LEVEL[risk]]

    precision = CONFIDENCE_PRECISION.get(result_properties.get("nightvision-confidence"), "medium")
    if PRECISION_ORDER.index(precision) > PRECISION_ORDER.index(props.get("precision", "low")):
        props["precision"] = precision

    tags = ["security", "dast", "nightvision"]
    cwe = cwe_for(rule_name)
    if cwe:
        tags.append(f"external/cwe/cwe-{cwe}")
    props["tags"] = tags

    # Rule help is shared by every result of the rule; build it once from the first description.
    body = parsed["description"] or FALLBACK_HELP.get(cwe)
    if "_nv_help" not in props and body:
        props["_nv_help"] = True
        footer = (
            "\n\n---\n"
            "Found by **NightVision DAST**: the check ran against the running application, "
            "and each alert links to the request and response that prove it."
        )
        if cwe:
            footer += f" Classified as [CWE-{cwe}](https://cwe.mitre.org/data/definitions/{cwe}.html)."
        rule["help"] = {"text": to_plain(body), "markdown": body + footer}
        summary = re.sub(r"^Summary\s*", "", to_plain(body))
        rule["fullDescription"] = {"text": summary.split("\n\n")[0][:1000]}
    rule["shortDescription"] = {"text": rule_name}
    rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe}.html" if cwe else "https://docs.nightviz.ai"


def finalize_rules(sarif):
    for run in sarif.get("runs", []):
        for rule in run["tool"]["driver"].get("rules", []):
            for key in ("_nv_risk", "_nv_help"):
                rule.get("properties", {}).pop(key, None)


def write_summary(path, findings, dropped, scan_url):
    counts = {risk: sum(1 for f in findings if f["risk"] == risk) for risk in reversed(RISK_ORDER)}
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    alerts = f"{server}/{repo}/security/code-scanning?query=is%3Aopen+tool%3ANightVision"
    pr = os.environ.get("NIGHTVISION_PR_NUMBER")
    if pr:
        alerts += f"+pr%3A{pr}"

    out = ["## NightVision DAST results", ""]
    out.append(" · ".join(f"{RISK_ICON[r]} **{counts[r]}** {r.title()}" for r in counts if r != "INFO"))
    out.append("")
    links = [f"[Code Scanning alerts]({alerts})"]
    if scan_url:
        links.insert(0, f"[Full scan in NightVision]({scan_url})")
    out += [" · ".join(links), ""]

    if findings:
        out += ["| Severity | Finding | Endpoint | Code | Proof |", "|---|---|---|---|---|"]
        for f in sorted(findings, key=lambda f: -RISK_ORDER.index(f["risk"])):
            code = f"`{f['file']}`"
            if f["file"] and repo and sha:
                code = f"[`{os.path.basename(f['file'])}:{f['line']}`]({server}/{repo}/blob/{sha}/{f['file']}#L{f['line']})"
            proof = f"[view]({f['link']})" if f["link"] else ""
            out.append(f"| {RISK_ICON[f['risk']]} {f['risk'].title()} | {f['name']} | `{f['where']}` | {code} | {proof} |")
    else:
        out.append("No findings at or above the reporting threshold.")
    if dropped:
        out += ["", f"<sub>{dropped} informational or duplicate results left out of Code Scanning; "
                    "they are in the raw SARIF artifact and in NightVision.</sub>"]

    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="SARIF file from `nightvision export sarif`")
    parser.add_argument("-o", "--output", help="output path (default: overwrite input)")
    parser.add_argument("--min-risk", default="LOW", type=str.upper, choices=RISK_ORDER,
                        help="drop results below this NightVision risk (default: LOW, which drops INFO)")
    parser.add_argument("--fallback-file", default="src/main/java/hawk/Application.java",
                        help="repo file to anchor findings NightVision could not trace to source")
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"),
                        help="append a Markdown summary here (default: $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as handle:
        sarif = json.load(handle)
    scan_url = next((run["tool"]["driver"].get("informationUri") for run in sarif.get("runs", [])), None)

    sarif, findings, dropped = enrich(sarif, args.min_risk, args.fallback_file)
    finalize_rules(sarif)

    with open(args.output or args.input, "w", encoding="utf-8") as handle:
        json.dump(sarif, handle, indent=2)
    if args.summary:
        write_summary(args.summary, findings, dropped, scan_url)

    print(f"NightVision SARIF: {len(findings)} results kept, {dropped} informational/duplicate dropped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
