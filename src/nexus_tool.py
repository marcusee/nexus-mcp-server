"""
Nexus IQ Remediation MCP Server

Exposes a small set of Nexus IQ endpoints as MCP tools so an LLM can
locate scans and reason about vulnerabilities for remediation.

Tools:
  - list_reports              -> /api/v2/reports/applications/{applicationId}
  - get_report                -> follow reportDataUrl from list_reports
  - get_vulnerable_components (filtered view of the raw report)
  - get_vulnerability         -> /api/v2/vulnerabilities/{refId}

Typical end-to-end flow (user supplies the application's internal id):
  1. list_reports(application_id)             -> entries with reportDataUrl per stage
  2. get_vulnerable_components(reportDataUrl) -> compact worklist
  3. get_vulnerability(refId) for each issue  -> details for remediation

The reports list already contains the URL to each scan's raw data, so
there is no need to thread a separate scan_id through the tools — the
model just passes the reportDataUrl back in.

Auth: HTTP Basic, credentials supplied via environment variables:
  NEXUS_IQ_BASE_URL   e.g. https://nexus-iq.example.com
  NEXUS_IQ_USERNAME   IQ user / token user
  NEXUS_IQ_PASSWORD   IQ password / user token code
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
# HTTP client
# ---------------------------------------------------------------------------

_client = httpx.Client(
    base_url=BASE_URL,
    auth=(USERNAME, PASSWORD),
    timeout=httpx.Timeout(60.0, connect=10.0),
    headers={"Accept": "application/json"},
)


def _get(path: str) -> Any:
    """GET a Nexus IQ JSON endpoint, raising on HTTP errors."""
    resp = _client.get(path)
    if resp.status_code == 401:
        raise RuntimeError(
            "Nexus IQ rejected credentials (401). "
            "Check NEXUS_IQ_USERNAME / NEXUS_IQ_PASSWORD."
        )
    if resp.status_code == 404:
        raise RuntimeError(f"Nexus IQ returned 404 for {path}")
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
def list_reports(application_id: str) -> list:
    """
    List all evaluation reports/scans for an application.

    Calls: GET /api/v2/reports/applications/{applicationId}

    Args:
        application_id: The application's INTERNAL id (the `id` field
            in /api/v2/applications, e.g.
            "f81a5c32544e4d55be8a0d0651dd7145"). NOT the publicId.
            Users find this via the Swagger UI, the IQ admin pages,
            or by calling /api/v2/applications themselves.

    Returns:
        A list of report summaries. Each entry includes a `reportDataUrl`
        (the path to the raw report) — pass that back into get_report or
        get_vulnerable_components without parsing out a scan id. Typical
        entry:
            {
              "stage": "build",          # build | stage-release | release | operate | ...
              "applicationId": "f81a5c32544e4d55be8a0d0651dd7145",
              "evaluationDate": "2026-05-01T10:42:15.212+01:00",
              "latestReportHtmlUrl": "ui/links/application/.../latestReport/build",
              "reportHtmlUrl": "ui/links/application/.../report/...",
              "embeddableReportHtmlUrl": "ui/links/application/.../report/.../embeddable",
              "reportPdfUrl": "ui/links/application/.../report/.../pdf",
              "reportDataUrl": "api/v2/applications/.../reports/.../raw"
            }
    """
    return _get(f"/api/v2/reports/applications/{application_id}")


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
    return _get(_normalize_report_url(report_data_url))


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
    report = _get(_normalize_report_url(report_data_url))

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
    return _get(f"/api/v2/vulnerabilities/{ref_id}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()