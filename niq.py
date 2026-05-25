from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from fastmcp import Context, FastMCP
from fastmcp.elicitation import AcceptedElicitation

# ---------------------------------------------------------------------------
# Configuration (set via environment variables)
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("NEXUS_IQ_BASE_URL", "").rstrip("/")
USERNAME = os.environ.get("NEXUS_IQ_USERNAME", "")
PASSWORD = os.environ.get("NEXUS_IQ_PASSWORD", "")
RBAC_BASE_URL = os.environ.get(
    "RBAC_BASE_URL", "????"
).rstrip("/")
NEXUS_REPO_BASE_URL = os.environ.get("NEXUS_REPO_BASE_URL", "").rstrip("/")

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
    verify=""
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
    verify=""
)

# Client for the Nexus Repository Manager search API (no auth).
_nexus_repo_client = httpx.Client(
    base_url=NEXUS_REPO_BASE_URL,
    timeout=httpx.Timeout(30.0, connect=10.0),
    headers={"Accept": "application/json"},
) if NEXUS_REPO_BASE_URL else None


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
      - absolute:           "https://it4it-nexus-iq-uat.swissbank.com/api/v2/.../raw"

    Returns a URL the configured httpx client can GET. If it's an
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
        return parsed.geturl()

    if not report_data_url.startswith("/"):
        report_data_url = "/" + report_data_url
    return BASE_URL.rstrip("/") + report_data_url


_RAW_REPORT_PATH_RE = re.compile(
    r"^/api/v2/applications/(?P<app>[^/]+)/reports/(?P<report>[^/]+)/raw$"
)


def _severity_score(issue: dict) -> float:
    """Return a numeric severity score for stable sorting."""
    try:
        value = issue.get("severity")
        if value is None:
            return -1.0
        return float(value)
    except (TypeError, ValueError):
        return -1.0


def _flatten_report_issues(report: dict) -> list[dict]:
    """Flatten report components into selectable issue rows."""
    rows: list[dict] = []
    for component in report.get("components", []):
        sec = component.get("securityData") or {}
        dep = component.get("dependencyData") or {}
        for issue in sec.get("securityIssues") or []:
            if _severity_score(issue) < 7.0:
                continue
            rows.append(
                {
                    "packageUrl": component.get("packageUrl"),
                    "hash": component.get("hash"),
                    "componentIdentifier": component.get("componentIdentifier"),
                    "directDependency": dep.get("directDependency"),
                    "parentComponentPurls": dep.get("parentComponentPurls") or [],
                    "issue": issue,
                }
            )
    rows.sort(key=lambda row: _severity_score(row["issue"]), reverse=True)
    return rows


def _severity_label(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _short_package_name(package_url: str | None) -> str:
    """Extract 'name@version' from a purl, e.g. pkg:npm/lodash@4.17.15 -> lodash@4.17.15."""
    if not package_url:
        return "unknown"
    # strip pkg:type/ prefix, take last path segment (handles group/name)
    raw = package_url.split(":", 1)[-1]          # npm/lodash@4.17.15
    raw = raw.split("/", 1)[-1] if "/" in raw else raw  # lodash@4.17.15 or group/name@ver
    return raw.rsplit("/", 1)[-1]                # take last segment for maven group paths


def _package_choice_title(package_url: str, pkg_rows: list[dict]) -> str:
    """Build a concise label for a package aggregating all its CVEs."""
    max_sev = max(_severity_score(r["issue"]) for r in pkg_rows)
    label = _severity_label(max_sev)
    score = f"{max_sev:.1f}"
    pkg = _short_package_name(package_url)
    refs = ", ".join(r["issue"].get("reference") or "?" for r in pkg_rows[:3])
    extra = f" +{len(pkg_rows) - 3} more" if len(pkg_rows) > 3 else ""
    return f"[{label} {score}]  {pkg}  —  {len(pkg_rows)} CVE(s): {refs}{extra}"


def _get_latest_package_version(package_url: str) -> dict:
    """Core logic for querying Nexus Repository for the latest version of a package."""
    if not _nexus_repo_client:
        raise RuntimeError(
            "NEXUS_REPO_BASE_URL is not set — cannot query Nexus Repository."
        )

    raw = package_url
    if raw.startswith("pkg:"):
        raw = raw[4:]
    purl_type, _, rest = raw.partition("/")
    purl_type = purl_type.lower()

    _PURL_TO_NEXUS_FORMAT = {
        "npm": "npm",
        "maven": "maven2",
        "golang": "go",
        "go": "go",
        "pypi": "pypi",
        "nuget": "nuget",
        "rubygems": "rubygems",
        "composer": "composer",
    }
    fmt = _PURL_TO_NEXUS_FORMAT.get(purl_type, purl_type)

    name_part = rest.rsplit("/", 1)[-1]
    name, _, _ = name_part.partition("@")

    resp = _nexus_repo_client.get(
        "/service/rest/v1/search",
        params={"format": fmt, "name": name, "sort": "version", "direction": "desc"},
    )
    if resp.status_code in (400, 404):
        raise RuntimeError(
            f"Nexus Repository returned {resp.status_code} for {fmt}/{name}."
        )
    resp.raise_for_status()

    items = resp.json().get("items") or []
    versions = list(dict.fromkeys(
        item["version"] for item in items if item.get("version")
    ))
    if not versions:
        raise RuntimeError(
            f"No versions found in Nexus Repository for {fmt}/{name}."
        )
    return {"package": name, "format": fmt, "latest": versions[0], "versions": versions[:20]}


def _try_get_latest_package_version(package_url: str) -> dict | None:
    """Like _get_latest_package_version but returns None on any error."""
    try:
        return _get_latest_package_version(package_url)
    except Exception:
        return None


def _purl_version(package_url: str | None) -> str | None:
    """Extract the version from a purl, e.g. pkg:npm/lodash@4.17.15 -> 4.17.15."""
    if not package_url:
        return None
    name_part = package_url.rsplit("/", 1)[-1]   # lodash@4.17.15 or name@ver
    return name_part.rsplit("@", 1)[-1] if "@" in name_part else None


def _issue_detail(row: dict) -> dict:
    """One CVE, trimmed to what's needed to choose a safe version.

    The full /api/v2/vulnerabilities/{refId} payload is mostly structured
    metadata remediation never reads, and it multiplies in fix_all mode, so we
    keep only the recommendation text and a reference link.
    """
    ref_id = row["issue"].get("reference")
    vuln = _iq_get(f"/api/v2/vulnerabilities/{ref_id}") if ref_id else {}
    return {
        "packageUrl": row.get("packageUrl"),
        "reference": ref_id,
        "severity": row["issue"].get("severity"),
        "recommendationMarkdown": vuln.get("recommendationMarkdown"),
        "vulnerabilityLink": vuln.get("vulnerabilityLink"),
    }


def _summarize_packages(rows: list[dict]) -> list[dict]:
    """Collapse CVE rows into one actionable entry per package, severity-sorted.

    This is the table a remediating agent needs to edit a manifest (current vs.
    latest version, direct/transitive). latestVersion is looked up once per
    package, not per CVE.
    """
    by_pkg: dict[str, dict] = {}
    for row in rows:
        purl = row.get("packageUrl") or "unknown"
        sev = _severity_score(row["issue"])
        entry = by_pkg.get(purl)
        if entry is None:
            by_pkg[purl] = {
                "packageUrl": purl,
                "name": _short_package_name(purl).rsplit("@", 1)[0],
                "currentVersion": _purl_version(purl),
                "latestVersion": (_try_get_latest_package_version(purl) or {}).get("latest"),
                "directDependency": row.get("directDependency"),
                "parentComponentPurls": row.get("parentComponentPurls") or [],
                "maxSeverity": sev,
                "cveCount": 1,
            }
        else:
            entry["maxSeverity"] = max(entry["maxSeverity"], sev)
            entry["cveCount"] += 1
    return sorted(by_pkg.values(), key=lambda e: e["maxSeverity"], reverse=True)


def _iq_get_maybe_404(url: str, params: dict | None = None) -> httpx.Response:
    """GET a Nexus IQ endpoint, but don't raise for 404."""
    resp = _iq_client.get(url, params=params)
    if resp.status_code == 401:
        raise RuntimeError(
            "Nexus IQ rejected credentials (401). "
            "Check NEXUS_IQ_USERNAME / NEXUS_IQ_PASSWORD."
        )
    if resp.status_code != 404:
        resp.raise_for_status()
    return resp


def _rewrite_raw_report_url_to_internal(raw_url: str) -> str:
    """Rewrite /api/v2/applications/{publicId}/reports/.../raw -> internal app id."""
    parsed = urlparse(raw_url)
    match = _RAW_REPORT_PATH_RE.match(parsed.path)
    if not match:
        return raw_url

    app_part = match.group("app")

    # Only rewrite numeric publicIds.
    if not app_part.isdigit():
        return raw_url

    app_lookup = _iq_get("/api/v2/applications", params={"publicId": app_part})
    apps = app_lookup.get("applications") or []
    if not apps or not apps[0].get("id"):
        raise RuntimeError(f"No Nexus IQ application has publicId={app_part!r}.")

    internal_id = apps[0]["id"]
    new_path = parsed.path.replace(
        f"/api/v2/applications/{app_part}/",
        f"/api/v2/applications/{internal_id}/",
        1,
    )
    return parsed._replace(path=new_path).geturl()


def _fetch_raw_report(report_data_url: str) -> dict:
    """Fetch a raw report, retrying with internal app id if the first URL 404s."""
    url1 = _normalize_report_url(report_data_url)
    resp1 = _iq_get_maybe_404(url1)
    if resp1.status_code != 404:
        return resp1.json()

    url2 = _rewrite_raw_report_url_to_internal(url1)
    if url2 != url1:
        resp2 = _iq_get_maybe_404(url2)
        if resp2.status_code != 404:
            return resp2.json()

    raise RuntimeError(f"Nexus IQ returned 404 for {url1}")


_AA_RE = re.compile(r"(?i)^AA\d+$")


def _list_projects_for_aa(aa_number: str) -> dict:
    """Look up GitLab projects mapped to an AA number via the RBAC API."""
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
        {"projectId": str(p.get("projectId")), "projectUri": p.get("projectUri")}
        for p in projects_raw
    ]
    return {
        "aa_number": aa_number,
        "appdir_id": payload.get("appdirId"),
        "name": payload.get("name"),
        "project_count": len(projects),
        "projects": projects,
    }


def _find_application_by_public_id(public_id: str) -> dict:
    """Resolve a Nexus IQ application by its publicId (a GitLab project id).

    Server-side filtered (GET /api/v2/applications?publicId=...), not a catalog
    scan, so it stays fast even on instances with tens of thousands of apps.
    """
    resp = _iq_get("/api/v2/applications", params={"publicId": public_id})
    apps = resp.get("applications") or []
    if not apps:
        raise RuntimeError(
            f"No Nexus IQ application has publicId={public_id!r}. "
            f"The project may not be onboarded for scanning."
        )
    return apps[0]


def _application_choice_title(app: dict) -> str:
    """Concise label for interactive application selection."""
    name = app.get("name") or "unknown-app"
    public_id = app.get("publicId") or "?"
    uri = app.get("projectUri") or ""
    return f"{name}  (publicId={public_id})  {uri}".rstrip()


# ---------------------------------------------------------------------------
# MCP tool registration
# ---------------------------------------------------------------------------

def register_this(mcp: FastMCP) -> None:
    """
    Nexus IQ Remediation MCP Server

    Exposes a small set of Nexus IQ endpoints (plus an internal AA-number ->
    GitLab projects lookup) as MCP tools so an LLM can locate scans and
    reason about vulnerabilities for remediation.

    Tools:
    - resolve_application_id   -> AA number OR publicId -> IQ applicationId(s)
    - list_reports            -> latest report via /api/v2/reports/applications/{applicationId}/history?limit=1
    - get_remediation_plan    -> pick one issue (or ALL) and get remediation info
    - get_latest_package_version -> latest version of a package in Nexus Repository

    Identifying the target application:
    - AA number: call resolve_application_id. If the AA maps to several
      applications the user is prompted to choose one; a single match is
      returned directly.
    - publicId provided: call resolve_application_id with the publicId — it
      resolves directly to a single application.
    - internal applicationId provided: skip to list_reports directly.

    Typical end-to-end flow (user supplies an AA number, e.g. "AA47794"):
        1. resolve_application_id("AA47794") -> user picks one application (if
           multiple) -> applications[0].applicationId
        2. list_reports(applicationId) -> latest report (reportDataUrl)
        3. get_remediation_plan(reportDataUrl) -> user picks one issue (or ALL)
        4. Remediate only the selected issue(s); use get_latest_package_version
           when a recommendation does not state a fixed version

    Auth:
    - Nexus IQ:       HTTP Basic from NEXUS_IQ_USERNAME / NEXUS_IQ_PASSWORD
    - AA mapping API: ungated POST (no credentials sent)

    Environment:
    NEXUS_IQ_BASE_URL   e.g. https://it4it-nexus-iq-uat.swissbank.com
    NEXUS_IQ_USERNAME   IQ user / token user
    NEXUS_IQ_PASSWORD   IQ password / user token code
    RBAC_BASE_URL       Base URL for the AA-mapping API
                        e.g. https://gitlab-rbac.ubs.net/
                        (defaults to https://gitlab-rbac.ubs.net/)
    """

    @mcp.tool()
    async def resolve_application_id(ctx: Context, identifier: str) -> dict:
        """
        Step 0 of remediation: resolve a Nexus IQ internal applicationId from
        either an AA number or a GitLab project publicId.

        - AA number (e.g. "AA47794"): looks up every GitLab project mapped to
          that AA and resolves each to its IQ application. If more than one
          application is found, the user is prompted to choose one, and only the
          chosen application is returned. Projects never onboarded to IQ are
          listed in `unmapped_projects`, not failed.
        - publicId (a GitLab project id, e.g. "271098"): resolves directly to
          the single application.

        Args:
            ctx: MCP context used to prompt the user when an AA maps to several
                applications.
            identifier: An AA number ("AA47794") or a GitLab project publicId
                ("271098").

        Returns:
            {
                "identifier": "AA47794",
                "kind": "aa",                       # "aa" | "public_id"
                "applications": [                   # one entry once selected
                    {
                        "applicationId": "f81a5c...",  # internal id -> list_reports
                        "publicId": "271098",
                        "name": "...",
                        "projectUri": "https://devcloud.example.net/.../da-deploy"
                    }
                ],
                "unmapped_projects": [              # AA only; [] for publicId
                    {"projectId": "265215", "projectUri": "...", "reason": "..."}
                ],
                "errors": [                         # AA only; [] for publicId
                    {"projectId": "...", "error": "..."}
                ]
            }

        Next step: take applications[0].applicationId, then call
        list_reports(applicationId).
        """
        identifier = identifier.strip()

        # publicId path: a GitLab project id resolves to exactly one application.
        if not _AA_RE.match(identifier):
            app = _find_application_by_public_id(identifier)
            return {
                "identifier": identifier,
                "kind": "public_id",
                "applications": [
                    {
                        "applicationId": app["id"],
                        "publicId": app.get("publicId"),
                        "name": app.get("name"),
                        "projectUri": None,
                    }
                ],
                "unmapped_projects": [],
                "errors": [],
            }

        # AA path: fan out to every mapped project and resolve each.
        mapping = _list_projects_for_aa(identifier)
        applications: list[dict] = []
        unmapped: list[dict] = []
        errors: list[dict] = []

        for project in mapping["projects"]:
            project_id = project["projectId"]
            try:
                app = _find_application_by_public_id(project_id)
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

            applications.append(
                {
                    "applicationId": app["id"],
                    "publicId": app.get("publicId"),
                    "name": app.get("name"),
                    "projectUri": project["projectUri"],
                }
            )

        # When an AA maps to several applications, let the user pick one.
        if len(applications) > 1:
            choices = {
                str(idx): {"title": _application_choice_title(app)}
                for idx, app in enumerate(applications, start=1)
            }
            selection = await ctx.elicit(
                (
                    f"AA {identifier} maps to {len(applications)} applications. "
                    "Which one do you want to remediate?"
                ),
                choices,
            )
            if not isinstance(selection, AcceptedElicitation):
                raise ValueError("Application selection cancelled.")
            selected_index = int(selection.data) - 1
            if selected_index < 0 or selected_index >= len(applications):
                raise ValueError("Invalid application selection.")
            applications = [applications[selected_index]]

        return {
            "identifier": identifier,
            "kind": "aa",
            "applications": applications,
            "unmapped_projects": unmapped,
            "errors": errors,
        }

    @mcp.tool()
    async def list_reports(application_id: str) -> list:
        """
        Get the latest evaluation report for one Nexus IQ application.

        Calls: GET /api/v2/reports/applications/{applicationId}/history?limit=1

        The history endpoint returns reports newest-first, so limit=1 yields the
        single most recent scan across all stages.

        Args:
            application_id: The application's INTERNAL id (the `applicationId`
                field from resolve_application_id, e.g.
                "f81a5c32544e4d55be8a0d0651dd7145"). NOT the publicId.

        Returns:
            A single-element list holding the most recent report (empty if the
            application has never been scanned). The entry includes a
            `reportDataUrl` (the path to the raw report) — pass that back into
            get_report or get_remediation_plan without parsing out a scan id.
            Typical entry:
            {
                "stage": "build",           # build | stage-release | release | operate | ...
                "applicationId": "f81a5c...",
                "evaluationDate": "2026-05-01T10:42:15.212+01:00",
                "latestReportHtmlUrl": "ui/links/application/.../latestReport/build",
                "reportHtmlUrl": "ui/links/application/.../report/...",
                "embeddableReportHtmlUrl": "ui/links/application/.../report/.../embeddable",
                "reportPdfUrl": "ui/links/application/.../report/.../pdf",
                "reportDataUrl": "api/v2/applications/.../reports/.../raw",
                "scanId": "...",
                "policyEvaluationId": "..."
            }
        """
        history = _iq_get(
            f"/api/v2/reports/applications/{application_id}/history",
            params={"limit": 1},
        )
        if not isinstance(history, dict):
            return []
        return history.get("reports") or []



    @mcp.tool()
    async def get_remediation_plan(ctx: Context, report_data_url: str) -> dict:
        """
        Use this to get remediation info for a report's vulnerabilities.

        Fetches one report, groups vulnerabilities by package, and asks the user
        to pick a package (fixing all its CVEs) or "Fix ALL". Returns a compact
        per-package table (`packages`) plus trimmed per-CVE detail (`issues`) and
        step-by-step remediation instructions for the assistant.

        After calling this tool, follow these steps to remediate:
        1. Determine the safe version per package: prefer a version named in the
           package's CVE recommendationMarkdown (in `issues`), else use the
           package's `latestVersion` (see next_action_for_assistant).
        2. Apply the fix based on `directDependency` (already in `packages`):
             - direct: bump the package's version in its manifest
               (npm->package.json, maven->pom.xml, golang->go.mod,
                pypi->requirements.txt/pyproject.toml, nuget->*.csproj).
             - transitive (directDependency=false): PIN to the safe version via
               the ecosystem's override mechanism (npm overrides, yarn
               resolutions, maven dependencyManagement, gradle constraints, go
               replace, nuget CPM). `parentComponentPurls` is context only.
        3. Stop after saving — do not run any package manager; do not fix other
           packages unless the user explicitly asks.

        Args:
            ctx: MCP context used to prompt user selection.
            report_data_url: The `reportDataUrl` from list_reports.

        Returns:
            `mode` is "fix_package" (one package's CVEs) or "fix_all" (every
            package). "fix_package" also carries the selected `packageUrl`.
            Otherwise both modes share the same shape:
            {
                "report_data_url": "...",
                "mode": "fix_all",
                "packages": [                       # actionable table, severity-sorted
                    {
                        "packageUrl": "pkg:npm/lodash@4.17.15",
                        "name": "lodash",
                        "currentVersion": "4.17.15",
                        "latestVersion": "4.17.21",     # may be null
                        "directDependency": true,
                        "parentComponentPurls": [],
                        "maxSeverity": 8.7,
                        "cveCount": 3
                    },
                    ...
                ],
                "issues": [                         # per-CVE detail, keyed by packageUrl
                    {
                        "packageUrl": "pkg:npm/lodash@4.17.15",
                        "reference": "sonatype-2024-3350",
                        "severity": 8.7,
                        "recommendationMarkdown": "Upgrade to lodash >= 4.17.21 ...",  # may be null
                        "vulnerabilityLink": "..."      # may be null
                    },
                    ...
                ],
                "next_action_for_assistant": "..."
            }
        """
        report = _fetch_raw_report(report_data_url)
        rows = _flatten_report_issues(report)
        if not rows:
            raise RuntimeError(
                "No vulnerable issues found in report. Nothing to remediate."
            )

        # Group rows by packageUrl; preserve severity-sorted order within each package.
        pkg_map: dict[str, list[dict]] = {}
        for row in rows:
            key = row.get("packageUrl") or "unknown"
            pkg_map.setdefault(key, []).append(row)

        sorted_pkgs = sorted(
            pkg_map.items(),
            key=lambda kv: max(_severity_score(r["issue"]) for r in kv[1]),
            reverse=True,
        )

        choices = {
            "all": {"title": f"Fix ALL {len(sorted_pkgs)} package(s)"},
            **{
                pkg_url: {"title": _package_choice_title(pkg_url, pkg_rows)}
                for pkg_url, pkg_rows in sorted_pkgs
            },
        }
        selection = await ctx.elicit(
            (
                f"Report has {len(rows)} CVE(s) across {len(sorted_pkgs)} package(s). "
                "Choose a package to fix all its CVEs, or choose 'Fix ALL' to remediate every CVE."
            ),
            choices,
        )

        if not isinstance(selection, AcceptedElicitation):
            raise ValueError("Issue selection cancelled.")

        # directDependency comes straight from the IQ report (component.dependencyData),
        # so the model never has to shell out (npm ls / mvn dependency:tree) to find out.
        # Direct deps: bump in the manifest. Transitive deps: pin to the safe version
        # via the ecosystem's override mechanism (deterministic), not by guessing a parent bump.
        _TRANSITIVE_GUIDANCE = (
            "Use the `directDependency` field to decide HOW to apply the fix — do NOT shell "
            "out to discover it (it is already in the data). "
            "IF directDependency is TRUE (declared directly): bump the package's version to the "
            "safe version in its manifest "
            "(npm->package.json, maven->pom.xml, gradle->build.gradle, golang->go.mod, "
            "pypi->requirements.txt/pyproject.toml, nuget->*.csproj) and save. "
            "IF directDependency is FALSE (transitive): the safe version is already known, so PIN it "
            "deterministically using the ecosystem's override mechanism rather than editing a parent: "
            "npm -> add/extend `overrides` in package.json; "
            "yarn -> `resolutions` in package.json; "
            "maven -> add the artifact to `<dependencyManagement>` with the safe version; "
            "gradle -> a dependency constraint (e.g. `constraints { implementation('grp:art:safeVer') }`); "
            "golang -> a `replace` directive in go.mod pinning the safe version; "
            "pypi -> add the package explicitly (or a constraints.txt entry) pinned to the safe version; "
            "nuget -> set the version centrally via Directory.Packages.props (CPM). "
            "`parentComponentPurls` lists the direct parent(s) that pull it in, for context only. "
            "After editing any dependency file, STOP — do NOT run npm install, mvn install, "
            "go mod tidy, pip install, dotnet restore, or any other package manager command."
        )

        _VERSION_RESOLUTION = (
            "To determine the safe version to upgrade a package to, follow this priority order — "
            "stop at the first step that gives a concrete version number: "
            "STEP A: Read the recommendationMarkdown of that package's CVEs in `issues` "
            "(match on packageUrl). If any states a specific version "
            "(e.g. 'upgrade to >= 4.17.21' or 'use 3.2.0+'), use the highest such version. "
            "STEP B (fallback only): If no recommendationMarkdown gives a version, use the "
            "`latestVersion` field on the package entry — it was pre-fetched for you. "
            "Do NOT call get_latest_package_version again."
        )

        multi_issue_instructions = (
            "Work through `packages` (already sorted by severity). For each package entry: "
            f"{_VERSION_RESOLUTION} "
            f"Then apply the fix based on the package's directDependency: {_TRANSITIVE_GUIDANCE} "
            "`issues` holds the per-CVE recommendation detail; `packages` is the actionable table."
        )

        if selection.data == "all":
            return {
                "report_data_url": report_data_url,
                "mode": "fix_all",
                "packages": _summarize_packages(rows),
                "issues": [_issue_detail(row) for row in rows],
                "next_action_for_assistant": multi_issue_instructions,
            }

        pkg_rows = pkg_map.get(selection.data)
        if pkg_rows is None:
            raise ValueError("Invalid package selection.")

        pkg_url = selection.data
        return {
            "report_data_url": report_data_url,
            "mode": "fix_package",
            "packageUrl": pkg_url,
            "packages": _summarize_packages(pkg_rows),
            "issues": [_issue_detail(row) for row in pkg_rows],
            "next_action_for_assistant": multi_issue_instructions,
        }
