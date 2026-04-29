"""
Nexus IQ Server vulnerability scanner.

Pulls the latest Application Composition Report for a given application
and lists every component along with its security vulnerabilities.

Usage:
    python nexus_iq_scanner.py <application_public_id> [--stage release|stage-release|build|operate]

Auth:
    Set NEXUS_IQ_URL, NEXUS_IQ_USER, NEXUS_IQ_TOKEN env vars.
    The user needs the "View IQ Elements" permission on the application.
"""

import os
import sys
import json
import argparse
from typing import Optional
import requests
from requests.auth import HTTPBasicAuth


class NexusIQClient:
    def __init__(self, base_url: str, user: str, token: str):
        # Normalize: strip trailing slash so we can join cleanly
        self.base_url = base_url.rstrip("/")
        self.auth = HTTPBasicAuth(user, token)
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({"Accept": "application/json"})

    def _get(self, path: str, **kwargs) -> dict:
        url = f"{self.base_url}{path}"
        r = self.session.get(url, timeout=30, **kwargs)
        r.raise_for_status()
        return r.json()

    def get_application(self, public_id: str) -> dict:
        """Resolve an application's internal ID from its public ID."""
        data = self._get("/api/v2/applications", params={"publicId": public_id})
        apps = data.get("applications", [])
        if not apps:
            raise ValueError(f"No application found with publicId={public_id!r}")
        return apps[0]

    def list_reports(self, application_id: str) -> list:
        """Return reports across all stages for the application."""
        return self._get(f"/api/v2/reports/applications/{application_id}")

    def get_latest_report(self, application_id: str, stage: Optional[str] = None) -> dict:
        """Pick the most recent report, optionally filtered by stage."""
        reports = self.list_reports(application_id)
        if stage:
            reports = [r for r in reports if r.get("stage") == stage]
        if not reports:
            raise ValueError(f"No reports found (stage={stage!r})")
        # evaluationDate is ISO 8601 — lexicographic sort works
        reports.sort(key=lambda r: r.get("evaluationDate", ""), reverse=True)
        return reports[0]

    def get_policy_report(self, report_link: str) -> dict:
        """
        Fetch the policy-evaluation view of a report. `report_link` looks like:
            ui/links/application/{publicId}/report/{reportId}
        We rewrite it to the policy API path.
        """
        # report_link example: "ui/links/application/MyApp/report/abc123"
        # We need: /api/v2/applications/{applicationId}/reports/{reportId}/policy
        # Easier: use the policyReportUrl from the report record if present,
        # otherwise build it from applicationId + reportDataUrl.
        return self._get("/" + report_link.lstrip("/"))

    def get_policy_report_by_ids(self, application_id: str, report_id: str) -> dict:
        return self._get(
            f"/api/v2/applications/{application_id}/reports/{report_id}/policy"
        )

    def get_raw_report_by_ids(self, application_id: str, report_id: str) -> dict:
        """Raw component report — has full component list with hashes/coordinates."""
        return self._get(
            f"/api/v2/applications/{application_id}/reports/{report_id}/raw"
        )


def extract_report_id(report_record: dict) -> str:
    """
    A report record from /api/v2/reports/applications/{appId} looks like:
        {
          "stage": "release",
          "evaluationDate": "2025-...",
          "reportHtmlUrl": "ui/links/application/MyApp/report/abc123def",
          "reportDataUrl": "api/v2/applications/<appId>/reports/abc123def/raw",
          "reportPdfUrl":  "api/v2/applications/<appId>/reports/abc123def/pdf",
          ...
        }
    The report ID is the trailing path segment.
    """
    data_url = report_record.get("reportDataUrl") or report_record.get("reportHtmlUrl", "")
    # Strip /raw or similar suffix if present, then take the segment before it
    parts = data_url.rstrip("/").split("/")
    # Find the segment after "reports"
    if "reports" in parts:
        idx = parts.index("reports")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    # Fallback: last segment of html url
    return data_url.rstrip("/").split("/")[-1]


def summarize_vulnerabilities(policy_report: dict, raw_report: dict) -> list[dict]:
    """
    Walk the policy report and produce one row per (component, vulnerability).
    Pulls component coordinates from the raw report when available.
    """
    # Build a lookup: componentIdentifier hash -> coordinates
    coord_lookup = {}
    for comp in raw_report.get("components", []):
        hash_ = comp.get("hash")
        if hash_:
            coord_lookup[hash_] = comp.get("componentIdentifier", {})

    rows = []
    for comp in policy_report.get("components", []):
        hash_ = comp.get("hash")
        ident = comp.get("componentIdentifier") or coord_lookup.get(hash_, {})
        coords = ident.get("coordinates", {}) if ident else {}
        display = " : ".join(
            v for v in (
                coords.get("groupId"),
                coords.get("artifactId") or coords.get("packageId") or coords.get("name"),
                coords.get("version"),
            ) if v
        ) or hash_ or "<unknown>"

        # Each component has a list of policyViolations; security ones carry CVE info
        sec_violations = [
            v for v in comp.get("violations", [])
            if "Security" in (v.get("policyName") or "")
            or v.get("constraints", [{}])[0].get("conditions", [{}])[0].get("conditionType") == "SecurityVulnerabilitySeverity"
        ]

        if not sec_violations:
            continue

        for v in sec_violations:
            # Dig out CVE / severity from the violation reasons
            for constraint in v.get("constraints", []):
                for cond in constraint.get("conditions", []):
                    reason = cond.get("conditionReason", "")
                    rows.append({
                        "component": display,
                        "policy": v.get("policyName"),
                        "threat_level": v.get("policyThreatLevel"),
                        "reason": reason,
                    })
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("public_id", help="Application public ID (as shown in IQ UI)")
    parser.add_argument("--stage", default=None,
                        help="release | stage-release | build | operate (default: latest of any)")
    parser.add_argument("--json", action="store_true", help="Emit raw JSON instead of a table")
    args = parser.parse_args()

    base_url = os.environ.get("NEXUS_IQ_URL")
    user = os.environ.get("NEXUS_IQ_USER")
    token = os.environ.get("NEXUS_IQ_TOKEN")
    if not all([base_url, user, token]):
        sys.exit("Set NEXUS_IQ_URL, NEXUS_IQ_USER, NEXUS_IQ_TOKEN.")

    client = NexusIQClient(base_url, user, token)

    app = client.get_application(args.public_id)
    app_id = app["id"]
    print(f"# Application: {app['name']} ({args.public_id})  internalId={app_id}", file=sys.stderr)

    report_record = client.get_latest_report(app_id, stage=args.stage)
    report_id = extract_report_id(report_record)
    print(f"# Latest report: stage={report_record.get('stage')} "
          f"evaluated={report_record.get('evaluationDate')}  reportId={report_id}",
          file=sys.stderr)

    policy_report = client.get_policy_report_by_ids(app_id, report_id)
    raw_report = client.get_raw_report_by_ids(app_id, report_id)

    rows = summarize_vulnerabilities(policy_report, raw_report)

    if args.json:
        json.dump(rows, sys.stdout, indent=2)
        return

    if not rows:
        print("No security violations on the latest report.")
        return

    # Simple text table
    print(f"{'Threat':<7} {'Component':<60} Reason")
    print("-" * 100)
    for r in sorted(rows, key=lambda x: -(x["threat_level"] or 0)):
        print(f"{r['threat_level']:<7} {r['component']:<60} {r['reason']}")


if __name__ == "__main__":
    main()
