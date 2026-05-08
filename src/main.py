"""
Nexus IQ Remediation MCP Server

Exposes a small set of Nexus IQ endpoints (plus an internal AA-number ->
GitLab projects lookup) as MCP tools so an LLM can locate scans and
reason about vulnerabilities for remediation.

Tools:
  - list_projects_for_aa            -> AA number -> list of GitLab projectIds
  - find_application_by_public_id   -> GitLab projectId -> IQ internal id
  - list_reports_for_aa             (chained) AA -> all reports per project
  - list_reports                    -> /api/v2/reports/applications/{applicationId}
  - get_report                      -> follow reportDataUrl from list_reports
  - get_vulnerable_components       (filtered view of the raw report)
  - get_vulnerability               -> /api/v2/vulnerabilities/{refId}

Typical end-to-end flow (user supplies an AA number, e.g. "AA47794"):
  Quick path:
    1. list_reports_for_aa("AA47794")            -> per-project report lists
    2. get_vulnerable_components(reportDataUrl)  -> compact worklist
    3. get_vulnerability(refId) for each issue   -> details for remediation

  Step-by-step path (model picks one project to drill into):
    1. list_projects_for_aa("AA47794")           -> projectIds + URIs
    2. find_application_by_public_id(projectId)  -> internal applicationId
    3. list_reports(applicationId)               -> reports for that one app
    4. get_vulnerable_components(reportDataUrl)
    5. get_vulnerability(refId)

Auth:
  - Nexus IQ:        HTTP Basic from NEXUS_IQ_USERNAME / NEXUS_IQ_PASSWORD
  - AA mapping API:  ungated POST (no credentials sent)
Environment:
  NEXUS_IQ_BASE_URL   e.g. https://nexus-iq.example.com
  NEXUS_IQ_USERNAME   IQ user / token user
  NEXUS_IQ_PASSWORD   IQ password / user token code
  RBAC_BASE_URL       Base URL for the AA-mapping API
                      e.g. ???
                      (defaults to ???)
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("NEXUS_IQ_BASE_URL", "").rstrip("/")
USERNAME = os.environ.get("NEXUS_IQ_USERNAME", "")
PASSWORD = os.environ.get("NEXUS_IQ_PASSWORD", "")
RBAC_BASE_URL = os.environ.get(
    "RBAC_BASE_URL", "????"
).rstrip("/")

_missing = [
    name
    for name, val in (
        ("NEXUS_IQ_BASE_URL", BASE_URL),
        ("NEXUS_IQ_USERNAME", USERNAME),
        ("NEXUS_IQ_PASSWORD", PASSWORD),
    )
    if not val
]
if _missing:
    raise RuntimeError(
        f"Missing required environment variables: {', '.join(_missing)}"
    )

# Hostname of the configured IQ server. Used to defend against the model
# passing in a fully-qualified URL pointing at some other host.
_BASE_HOST = urlparse(BASE_URL).netloc


# ---------------------------------------------------------------------------
# HTTP clients
# ---------------------------------------------------------------------------

_iq_client = httpx.Client(
    base_url=BASE_URL,
    auth=(USERNAME, PASSWORD),
    timeout=httpx.Timeout(60.0, connect=10.0),
    headers={"Accept": "application/json"},
)

# Client for the AA-number -> GitLab projects mapping API.
# Kept separate from _iq_client so IQ basic-auth is never sent here.
_aa_mapping_client = httpx.Client(
    base_url=RBAC_BASE_URL,
    timeout=httpx.Timeout(30.0, connect=10.0),
    headers={
        "Accept": "application/json",
        "Content-Type": "application/json",
    },
)


def _iq_get(path: str, params: dict | None = None) -> Any:
    """GET a Nexus IQ JSON endpoint, raising on HTTP errors."""
    resp = _iq_client.get(path, params=params)
    if resp.status_code == 401:
        raise RuntimeError(
            "Nexus IQ rejected credentials (401). "
            "Check NEXUS_IQ_USERNAME / NEXUS_IQ_PASSWORD."
        )
    if resp.status_code == 404:
        raise RuntimeError(f"Nexus IQ returned 404 for {path}")
    resp.raise_for_status()
    return resp.json()


def _aa_mapping_post(path: str, json_body: dict) -> Any:
    """POST to the AA-number -> GitLab projects mapping API."""
    resp = _aa_mapping_client.post(path, json=json_body)
    if resp.status_code == 404:
        raise RuntimeError(f"AA mapping API returned 404 for {path}")
    resp.raise_for_status()
    return resp.json()


def _normalize_report_url(report_data_url: str) -> str:
    """
    Accept the reportDataUrl in any of the shapes IQ tends to return it:
      - relative no-slash:  "api/v2/applications/foo/reports/abc/raw"
      - relative w/ slash:  "/api/v2/applications/foo/reports/abc/raw"
      - absolute:           "https://nexus-iq.example.com/api/v2/.../raw"

    Returns a path the configured httpx client can GET. If it's an
    absolute URL pointing at a different host, refuse — we don't want
    the model talking us into making requests to arbitrary servers
    with our basic-auth credentials attached.
    """
    if report_data_url.startswith(("http://", "https://")):
        parsed = urlparse(report_data_url)
        if parsed.netloc != _BASE_HOST:
            raise RuntimeError(
                f"reportDataUrl host {parsed.netloc!r} does not match "
                f"configured NEXUS_IQ_BASE_URL host {_BASE_HOST!r}."
            )
        return parsed.path
    if not report_data_url.startswith("/"):
        return "/" + report_data_url
    return report_data_url


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP("nexus-iq-remediation")


@mcp.tool()
def list_projects_for_aa(aa_number: str) -> dict:
    """
    Look up GitLab projects associated with an AA number via the RBAC API.

    Calls: POST {RBAC_BASE_URL}/api/v1/rbac:findRbacMapping
           body: {"swc": "<AA number>"}

    Args:
        aa_number: The AA number / SWC, e.g. "AA47794".

    Returns:
        {
          "aa_number": "AA47794",
          "appdir_id": "ABA834C73B684D03945FCFAC5081A484",
          "name": "rbac/AA47794/mapping/...",
          "project_count": 12,
          "projects": [
            {"projectId": "271098",
             "projectUri": "https://devcloud.example.net/.../da-deploy"},
            ...
          ]
        }

        The `projectId` values are what Nexus IQ stores as `publicId`
        for each application — pass them to find_application_by_public_id.

    Raises:
        RuntimeError if the AA number maps to zero projects.
    """
    payload = _aa_mapping_post(
        "/api/v1/rbac:findRbacMapping", json_body={"swc": aa_number}
    )

    projects_raw = payload.get("projects") or []
    if not projects_raw:
        raise RuntimeError(
            f"AA number {aa_number!r} has no GitLab projects in RBAC mapping."
        )

    # Normalise projectId to a string — IQ publicIds are strings, but the
    # RBAC API returns them as integers.
    projects = [
        {
            "projectId": str(p.get("projectId")),
            "projectUri": p.get("projectUri"),
        }
        for p in projects_raw
    ]

    return {
        "aa_number": aa_number,
        "appdir_id": payload.get("appdirId"),
        "name": payload.get("name"),
        "project_count": len(projects),
        "projects": projects,
    }


@mcp.tool()
def find_application_by_public_id(public_id: str) -> dict:
    """
    Look up a Nexus IQ application by its publicId (a GitLab project ID
    in this deployment) and return its internal applicationId.

    Calls: GET /api/v2/applications?publicId={publicId}

    This is server-side filtered, NOT a catalog scan, so it stays fast
    even on instances with tens of thousands of applications.

    Args:
        public_id: The application's publicId in Nexus IQ. In this
            deployment that is the GitLab project ID, e.g. "271098".

    Returns:
        {
          "id": "f81a5c32544e4d55be8a0d0651dd7145",  # internal id
          "publicId": "271098",
          "name": "...",
          "organizationId": "...",
          "contactUserName": null | "...",
          "applicationTags": [...]
        }

    Raises:
        RuntimeError if no application matches the publicId (e.g. the
        GitLab project has never been onboarded to Nexus IQ).
    """
    resp = _iq_get("/api/v2/applications", params={"publicId": public_id})
    apps = resp.get("applications") or []
    if not apps:
        raise RuntimeError(
            f"No Nexus IQ application has publicId={public_id!r}. "
            f"The project may not be onboarded for scanning."
        )
    return apps[0]


@mcp.tool()
def list_reports_for_aa(aa_number: str) -> dict:
    """
    Convenience tool: take an AA number, fan out to every associated
    GitLab project, and return Nexus IQ reports for each.

    Internally chains:
      1. list_projects_for_aa(aa_number)
      2. for each project: find_application_by_public_id + list_reports

    Projects that have no IQ application (never onboarded) are reported
    in `unmapped_projects` rather than failing the whole call. Other
    per-project errors land in `errors`.

    Args:
        aa_number: The AA number, e.g. "AA47794".

    Returns:
        {
          "aa_number": "AA47794",
          "project_count": 12,
          "mapped_count": 9,
          "results": [
            {
              "projectId": "271098",
              "projectUri": "...",
              "applicationId": "f81a5c...",
              "applicationPublicId": "271098",
              "applicationName": "...",
              "reports": [ {stage, evaluationDate, reportDataUrl, ...}, ... ]
            },
            ...
          ],
          "unmapped_projects": [
            {"projectId": "265215", "projectUri": "...",
             "reason": "No Nexus IQ application has publicId='265215'."}
          ],
          "errors": [
            {"projectId": "...", "error": "..."}
          ]
        }
    """
    mapping = list_projects_for_aa(aa_number)
    projects = mapping["projects"]

    results: list[dict] = []
    unmapped: list[dict] = []
    errors: list[dict] = []

    for project in projects:
        project_id = project["projectId"]
        try:
            app = find_application_by_public_id(project_id)
        except RuntimeError as exc:
            # Most common case: project not onboarded to IQ.
            unmapped.append(
                {
                    "projectId": project_id,
                    "projectUri": project["projectUri"],
                    "reason": str(exc),
                }
            )
            continue
        except httpx.HTTPError as exc:
            errors.append({"projectId": project_id, "error": str(exc)})
            continue

        try:
            reports = _iq_get(
                f"/api/v2/reports/applications/{app['id']}"
            )
        except (RuntimeError, httpx.HTTPError) as exc:
            errors.append({"projectId": project_id, "error": str(exc)})
            continue

        results.append(
            {
                "projectId": project_id,
                "projectUri": project["projectUri"],
                "applicationId": app["id"],
                "applicationPublicId": app.get("publicId"),
                "applicationName": app.get("name"),
                "reports": reports,
            }
        )

    return {
        "aa_number": aa_number,
        "project_count": mapping["project_count"],
        "mapped_count": len(results),
        "results": results,
        "unmapped_projects": unmapped,
        "errors": errors,
    }


@mcp.tool()
def list_reports(application_id: str) -> list:
    """
    List all evaluation reports/scans for one Nexus IQ application.

    Calls: GET /api/v2/reports/applications/{applicationId}

    Args:
        application_id: The application's INTERNAL id (the `id` field
            from find_application_by_public_id, e.g.
            "f81a5c32544e4d55be8a0d0651dd7145"). NOT the publicId.

    Returns:
        A list of report summaries. Each entry includes a `reportDataUrl`
        (the path to the raw report) — pass that back into get_report or
        get_vulnerable_components without parsing out a scan id. Typical
        entry:
            {
              "stage": "build",          # build | stage-release | release | operate | ...
              "applicationId": "f81a5c...",
              "evaluationDate": "2026-05-01T10:42:15.212+01:00",
              "latestReportHtmlUrl": "ui/links/application/.../latestReport/build",
              "reportHtmlUrl": "ui/links/application/.../report/...",
              "embeddableReportHtmlUrl": "ui/links/application/.../report/.../embeddable",
              "reportPdfUrl": "ui/links/application/.../report/.../pdf",
              "reportDataUrl": "api/v2/applications/.../reports/.../raw"
            }
    """
    return _iq_get(f"/api/v2/reports/applications/{application_id}")


@mcp.tool()
def get_report(report_data_url: str) -> dict:
    """
    Fetch the raw scan report by following a reportDataUrl returned from
    list_reports.

    Args:
        report_data_url: The `reportDataUrl` field from a list_reports
            entry. Accepts relative ("api/v2/applications/.../raw") or
            absolute ("https://nexus-iq.example.com/api/v2/...") forms.
            Absolute URLs must point at the configured IQ host.

    Returns:
        The raw report JSON. Components live under `components[]`, each
        with `securityData.securityIssues[]` whose `reference` field is
        the refId you pass to get_vulnerability().
    """
    return _iq_get(_normalize_report_url(report_data_url))


@mcp.tool()
def get_vulnerable_components(report_data_url: str) -> dict:
    """
    Convenience tool: fetch a raw report and return only the components
    with at least one security issue, alongside the refIds of those issues.

    Use this to get a compact worklist before iterating get_vulnerability()
    calls, instead of asking the model to scan the full raw report.

    Args:
        report_data_url: The `reportDataUrl` from a list_reports entry.

    Returns:
        {
          "report_data_url": "...",
          "vulnerable_component_count": 3,
          "components": [
            {
              "packageUrl": "pkg:maven/commons-collections/commons-collections@3.2.2?type=jar",
              "hash": "...",
              "componentIdentifier": {...},
              "issues": [
                {
                  "reference": "sonatype-2024-3350",
                  "severity": 8.7,
                  "source": "sonatype",
                  "status": "Open",
                  "url": "..."
                }
              ]
            }
          ]
        }
    """
    report = _iq_get(_normalize_report_url(report_data_url))

    vulnerable: list[dict] = []
    for component in report.get("components", []):
        sec = component.get("securityData") or {}
        issues = sec.get("securityIssues") or []
        if not issues:
            continue
        vulnerable.append(
            {
                "packageUrl": component.get("packageUrl"),
                "hash": component.get("hash"),
                "componentIdentifier": component.get("componentIdentifier"),
                "issues": issues,
            }
        )

    return {
        "report_data_url": report_data_url,
        "vulnerable_component_count": len(vulnerable),
        "components": vulnerable,
    }


@mcp.tool()
def get_vulnerability(ref_id: str) -> dict:
    """
    Fetch details for a single vulnerability by its reference ID.

    Calls: GET /api/v2/vulnerabilities/{refId}

    The returned payload typically contains description / explanation /
    detection / recommendation Markdown fields, plus CVSS scoring and
    CWE metadata. The recommendationMarkdown field is the main thing
    the LLM should use to draft a remediation suggestion.

    Args:
        ref_id: The vulnerability reference, e.g. "CVE-2021-44228" or
            "sonatype-2024-3350". This is the `reference` value found
            inside securityData.securityIssues[] in the scan report.
    """
    return _iq_get(f"/api/v2/vulnerabilities/{ref_id}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()