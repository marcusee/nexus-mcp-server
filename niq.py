from __future__ import annotions

import os
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from fastmcp import Context, FastMCP
from fastmcp.elicitation import AcceptedElicitation

import inspect
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


def _parse_iq_datetime(dt: str | None) -> datetime:
    """Parse Nexus IQ evaluationDate strings into a sortable datetime.

    Nexus IQ commonly returns ISO-8601 strings like:
      - 2024-03-07T15:30:43.442Z
      - 2026-05-01T01:16:35.012+01:00

    If parsing fails, returns datetime.min so those entries sort last.
    """
    if not dt or not isinstance(dt, str):
        return datetime.min
    try:
        # Python's fromisoformat doesn't accept the trailing 'Z'.
        return datetime.fromisoformat(dt.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min


def _sort_reports_newest_first(reports: list[dict]) -> list[dict]:
    return sorted(
        reports,
        key=lambda r: _parse_iq_datetime(r.get("evaluationDate")),
        reverse=True,
    )


def _report_choice_title(report: dict) -> str:
    """Build a concise, user-friendly label for interactive report selection."""
    stage = report.get("stage") or "unknown-stage"
    evaluation_date = report.get("evaluationDate") or "unknown-date"
    return f"stage={stage} scanned at {evaluation_date}"


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
        for issue in sec.get("securityIssues") or []:
            if _severity_score(issue) < 7.0:
                continue
            rows.append(
                {
                    "packageUrl": component.get("packageUrl"),
                    "hash": component.get("hash"),
                    "componentIdentifier": component.get("componentIdentifier"),
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


def _issue_choice_title(row: dict) -> str:
    issue = row["issue"]
    severity = issue.get("severity")
    label = _severity_label(severity)
    score = f"{severity:.1f}" if severity is not None else "?"
    reference = issue.get("reference") or "unknown-ref"
    pkg = _short_package_name(row.get("packageUrl"))
    return f"[{label} {score}]  {reference}  —  {pkg}"


def _get_sorted_reports(application_id: str) -> list[dict]:
    """Fetch and sort reports newest-first for one IQ application."""
    reports = _iq_get(f"/api/v2/reports/applications/{application_id}")
    if not isinstance(reports, list):
        return []
    return _sort_reports_newest_first(reports)

async def _select_single_report(
    ctx: Context,
    reports: list[dict],
    prompt_subject: str,
) -> list[dict]:
    """Prompt user to select one report when multiple are present."""
    if len(reports) <= 1:
        return reports

    choices = {
        str(idx): {"title": _report_choice_title(report)}
        for idx, report in enumerate(reports, start=1)
    }
    print(inspect.signature(ctx.elicit))
    print(ctx.elicit.__doc__)

    selection = await ctx.elicit(
        f"{prompt_subject} has {len(reports)} reports. Which one? ",
        choices,
    )

    if not isinstance(selection, AcceptedElicitation):
        raise ValueError("Report selection cancelled.")

    selected_index = int(selection.data) - 1
    if selected_index < 0 or selected_index >= len(reports):
        raise ValueError("Invalid report selection.")
    return [reports[selected_index]]


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
    - list_projects_for_aa          -> AA number -> list of GitLab projectIds
    - find_application_by_public_id -> GitLab projectId -> IQ internal id
    - list_reports_for_aa           (chained) AA -> one selected report per project
    - list_reports                  -> /api/v2/reports/applications/{applicationId}
    - get_report                    -> follow reportDataUrl from list_reports
    - get_vulnerable_components     (filtered view of the raw report)
    - choose_issue_for_remediation  -> ask user to pick one issue from a report
    - get_vulnerability             -> /api/v2/vulnerabilities/{refId}

    Identifying the target project automatically:
    Before asking the user which project to fix, read .git/config in the
    current working directory to get the remote origin URL. Use that URL to
    narrow down the target — depending on what the user provided:
    - AA number only: call list_projects_for_aa, then match remote origin URL
      against projectUri (case-insensitive, ignore .git suffix). Use the
      matching project; only ask the user if no match is found.
    - publicId provided: skip the AA lookup and go straight to
      find_application_by_public_id.
    - internal applicationId provided: skip to list_reports directly.

    Typical end-to-end flow (user supplies an AA number, e.g. "AA47794"):
    Quick path (single-issue remediation):
        1. Read .git/config -> get remote origin URL
        2. list_reports_for_aa("AA47794") -> match origin URL to one project
        3. get_vulnerable_components(reportDataUrl)  -> compact worklist
        4. choose_issue_for_remediation(reportDataUrl) -> user selects one issue
        5. Remediate only that selected issue

    Step-by-step path (model picks one project to drill into):
        1. Read .git/config -> get remote origin URL
        2. list_projects_for_aa("AA47794") -> match origin URL to projectId
        3. find_application_by_public_id(projectId)  -> internal applicationId
        4. list_reports(applicationId)               -> selected report
        5. choose_issue_for_remediation(reportDataUrl) -> user picks one issue
        6. Remediate only the selected issue

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
    async def list_reports_for_aa(ctx: Context, aa_number: str) -> dict:
        """
        Convenience tool: take an AA number, fan out to every associated
        GitLab project, and return Nexus IQ reports for each.

        If a project has multip[lre reports, the user is prompted to choose one
        report before this tool includes it in the output.

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
                reports = _get_sorted_reports(app["id"])
            except (RuntimeError, httpx.HTTPError) as exc:
                errors.append({"projectId": project_id, "error": str(exc)})
                continue
            reports = await _select_single_report(
                ctx,
                reports,
                prompt_subject=f"Project {project_id}",
            )

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
    async def list_reports(ctx: Context, application_id: str) -> list:
        """
        List all evaluation reports/scans for one Nexus IQ application.

        Calls: GET /api/v2/reports/applications/{applicationId}

        Args:
            application_id: The application's INTERNAL id (the `id` field
                from find_application_by_public_id, e.g.
                "f81a5c32544e4d55be8a0d0651dd7145"). NOT the publicId.

        Returns:
            A list of report summaries. If multiple reports exist, the user is
            prompted to manually choose one report to proceed and only the
            selected report is returned. Each entry includes a `reportDataUrl`
            (the path to the raw report) — pass that back into get_report or
            get_vulnerable_components without parsing out a scan id. Typical
            entry:
            {
                "stage": "build",           # build | stage-release | release | operate | ...
                "applicationId": "f81a5c...",
                "evaluationDate": "2026-05-01T10:42:15.212+01:00",
                "latestReportHtmlUrl": "ui/links/application/.../latestReport/build",
                "reportHtmlUrl": "ui/links/application/.../report/...",
                "embeddableReportHtmlUrl": "ui/links/application/.../report/.../embeddable",
                "reportPdfUrl": "ui/links/application/.../report/.../pdf",
                "reportDataUrl": "api/v2/applications/.../reports/.../raw"
            }
        """
        reports = _get_sorted_reports(application_id)
        return await _select_single_report(
            ctx,
            reports,
            prompt_subject=f"Application {application_id}",
        )


    @mcp.tool()
    def get_latest_report(application_id: str, stage: str | None = "release") -> dict:
        """Return the newest report for an app, optionally filtered by stage.

        Args:
            application_id: Internal Nexus IQ application id.
            stage: Optional stage name (e.g. "build", "release").
                Defaults to "release".

        Returns:
            The newest report summary dict (same shape as list_reports entries).

        Raises:
            RuntimeError if no reports exist (or none match stage).
        """
        reports = _get_sorted_reports(application_id)
        if not reports:
            raise RuntimeError(
                f"No Nexus IQ reports found for application_id={application_id!r}."
            )

        if stage:
            reports = [r for r in reports if r.get("stage") == stage]
            if not reports:
                raise RuntimeError(
                    f"No Nexus IQ reports found for application_id={application_id!r} "
                    f"with stage={stage!r}."
                )

        # list_reports() is already sorted newest-first.
        return reports[0]


    @mcp.tool()
    def get_report(report_data_url: str) -> dict:
        """
        Fetch the raw scan report by following a reportDataUrl returned from
        list_reports.

        Args:
            report_data_url: The `reportDataUrl` field from a list_reports
                entry. Accepts relative ("api/v2/applications/.../raw") or
                absolute ("https://it4it-nexus-iq-uat.swissbank.com/api/v2/...") forms.
                Absolute URLs must point at the configured IQ host.

        Returns:
            The raw report JSON. Components live under `components[]`, each
            with `securityData.securityIssues[]` whose `reference` field is
            the refId you pass to get_vulnerability().
        """
        return _fetch_raw_report(report_data_url)

    @mcp.tool()
    def get_vulnerable_components(report_data_url: str) -> dict:
        """
        Fetch a raw report and return a pre-ranked summary of vulnerable issues.

        Only includes issues with severity >= 7.0 OR threatCategory in
        ("critical", "severe"). Lower-severity issues are counted but omitted
        from top_issues unless the user explicitly asks for them.

        Do NOT run your own Python/scripts to re-parse the report after calling
        this tool — the ranking and filtering is already done. Show top_issues
        to the user, ask which one to fix, then call choose_issue_for_remediation.

        Args:
            report_data_url: The `reportDataUrl` from a list_reports entry.

        Returns:
            {
                "report_data_url": "...",
                "total_vulnerable_components": 12,
                "high_severity_issue_count": 5,
                "top_issues": [
                    {
                        "rank": 1,
                        "severity": 9.8,
                        "threat_category": "critical",
                        "reference": "CVE-2021-44228",
                        "source": "nvd",
                        "package": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        "status": "Open"
                    },
                    ...
                ],
                "next_action_for_assistant": "..."
            }
        """
        report = _fetch_raw_report(report_data_url)

        _HIGH_CATEGORIES = {"critical", "severe"}

        # Flatten to one row per issue, deduplicate by reference keeping max severity.
        best: dict[str, dict] = {}
        total_vulnerable = 0

        for component in report.get("components", []):
            sec = component.get("securityData") or {}
            issues = sec.get("securityIssues") or []
            if not issues:
                continue
            total_vulnerable += 1
            pkg_url = component.get("packageUrl") or ""
            for issue in issues:
                ref = issue.get("reference") or ""
                sev = issue.get("severity") or 0
                tc = (issue.get("threatCategory") or "").lower()
                if sev < 7.0 and tc not in _HIGH_CATEGORIES:
                    continue
                if ref not in best or sev > best[ref]["severity"]:
                    best[ref] = {
                        "reference": ref,
                        "severity": sev,
                        "threat_category": tc,
                        "source": issue.get("source") or "",
                        "status": issue.get("status") or "",
                        "package": pkg_url,
                    }

        ranked = sorted(best.values(), key=lambda r: r["severity"], reverse=True)
        top_issues = [{"rank": i + 1, **row} for i, row in enumerate(ranked)]

        return {
            "report_data_url": report_data_url,
            "total_vulnerable_components": total_vulnerable,
            "high_severity_issue_count": len(top_issues),
            "top_issues": top_issues,
            "next_action_for_assistant": (
                "Show top_issues to the user ranked by severity. "
                "For each issue: call get_latest_package_version(packageUrl) if "
                "recommendationMarkdown has no fixed version, then read the dependency "
                "file and bump the version. Do not run npm/shell commands to find versions — "
                "use get_latest_package_version instead."
            ),
        }



    @mcp.tool()
    async def choose_issue_for_remediation(ctx: Context, report_data_url: str) -> dict:
        """
        Fetch one report, ask the user to pick exactly one vulnerability issue,
        then return that issue plus full vulnerability details.

        Use this before remediation to avoid bulk fixing every issue in a report.

        After calling this tool, follow these steps to remediate:
        1. Read `vulnerability.recommendationMarkdown` — it contains the safe
           version or patch to apply.
        2. Decode the affected package from `selected.packageUrl`:
             pkg:maven/group/artifact@version  -> pom.xml / build.gradle
             pkg:npm/name@version              -> package.json
             pkg:pypi/name@version             -> requirements.txt / pyproject.toml
             pkg:nuget/name@version            -> *.csproj / packages.config
        3. Search the repo for the dependency declaration of that package.
        4. Update the version to the safe version from the recommendation.
        5. Stop — do not fix other issues unless the user explicitly asks.

        Args:
            ctx: MCP context used to prompt user selection.
            report_data_url: The `reportDataUrl` from list_reports/list_reports_for_aa.

        Returns:
            {
                "report_data_url": "...",
                "selected": {
                    "packageUrl": "pkg:npm/lodash@4.17.15",
                    "componentIdentifier": {...},
                    "issue": {
                        "reference": "sonatype-2024-3350",
                        "severity": 8.7,
                        ...
                    }
                },
                "vulnerability": {
                    "recommendationMarkdown": "Upgrade to lodash >= 4.17.21 ...",
                    ...
                },
                "next_action_for_assistant": "..."
            }
        """
        report = _fetch_raw_report(report_data_url)
        rows = _flatten_report_issues(report)
        if not rows:
            raise RuntimeError(
                "No vulnerable issues found in report. Nothing to remediate."
            )

        choices = {
            "all": {"title": f"Fix ALL {len(rows)} issues"},
            **{
                str(idx): {"title": _issue_choice_title(row)}
                for idx, row in enumerate(rows, start=1)
            },
        }
        selection = await ctx.elicit(
            (
                f"Report has {len(rows)} vulnerable issue(s). "
                "Choose one issue to remediate, or choose 'Fix ALL' to remediate every issue."
            ),
            choices,
        )

        if not isinstance(selection, AcceptedElicitation):
            raise ValueError("Issue selection cancelled.")

        # For transitive deps: prefer upgrading the direct parent over adding an override/exclude.
        # Each ecosystem has a shell command to trace which direct dep pulls in the transitive one;
        # upgrade that parent to its latest version so it brings in a safe transitive version.
        _TRANSITIVE_GUIDANCE = (
            "If the package is TRANSITIVE (not declared directly): "
            "DO NOT add an npm override, Maven exclusion, or similar workaround as a first resort. "
            "Instead, find the direct parent that pulls it in using the ecosystem-appropriate command: "
            "npm -> `npm ls <pkg>` or parse package-lock.json; "
            "maven -> `mvn dependency:tree -Dincludes=group:artifact`; "
            "go -> `go mod graph | grep <module>`; "
            "pypi -> `pip show <pkg>` (check Required-by) or parse poetry.lock/Pipfile.lock; "
            "nuget -> `dotnet list package --include-transitive`. "
            "Then call get_latest_package_version on the parent and upgrade it — "
            "the updated parent will pull in a safe version of the transitive dep. "
            "Only fall back to an override/exclude if no parent upgrade resolves it. "
            "After editing any dependency file, STOP — do NOT run npm install, mvn install, "
            "go mod tidy, pip install, dotnet restore, or any other package manager command."
        )

        _VERSION_RESOLUTION = (
            "To determine the safe version to upgrade to, follow this priority order — "
            "stop at the first step that gives a concrete version number: "
            "STEP A: Read vulnerability.recommendationMarkdown. "
            "If it contains a specific version (e.g. 'upgrade to >= 4.17.21' or 'use 3.2.0+'), use that version. "
            "STEP B (fallback only): If recommendationMarkdown is empty or contains no version number, "
            "call get_latest_package_version(packageUrl) and use the returned latest version. "
            "Do NOT call get_latest_package_version if STEP A already gave a version."
        )

        fix_all_instructions = (
            f"For each item in `issues`: {_VERSION_RESOLUTION} "
            "Then: decode the dependency file from item.packageUrl: "
            "npm->package.json, maven->pom.xml, golang->go.mod, pypi->requirements.txt, nuget->*.csproj. "
            "Read that file and confirm the package is a DIRECT dependency. "
            f"{_TRANSITIVE_GUIDANCE} "
            "If direct, bump the version to the safe version and save the file. "
            "Repeat for every item in the list."
        )

        if selection.data == "all":
            issues_with_vulns = []
            for row in rows:
                ref_id = row["issue"].get("reference")
                vulnerability = _iq_get(f"/api/v2/vulnerabilities/{ref_id}") if ref_id else {}
                issues_with_vulns.append({
                    "packageUrl": row.get("packageUrl"),
                    "hash": row.get("hash"),
                    "componentIdentifier": row.get("componentIdentifier"),
                    "issue": row["issue"],
                    "vulnerability": vulnerability,
                })
            return {
                "report_data_url": report_data_url,
                "mode": "fix_all",
                "issues": issues_with_vulns,
                "next_action_for_assistant": fix_all_instructions,
            }

        selected_index = int(selection.data) - 1
        if selected_index < 0 or selected_index >= len(rows):
            raise ValueError("Invalid issue selection.")

        selected = rows[selected_index]
        issue = selected["issue"]
        ref_id = issue.get("reference")
        if not ref_id:
            raise RuntimeError("Selected issue has no reference/refId.")

        vulnerability = _iq_get(f"/api/v2/vulnerabilities/{ref_id}")
        return {
            "report_data_url": report_data_url,
            "mode": "fix_one",
            "selected": {
                "packageUrl": selected.get("packageUrl"),
                "hash": selected.get("hash"),
                "componentIdentifier": selected.get("componentIdentifier"),
                "issue": issue,
            },
            "vulnerability": vulnerability,
            "next_action_for_assistant": (
                f"1. {_VERSION_RESOLUTION} "
                "2. Decode the dependency file from selected.packageUrl: "
                "npm->package.json, maven->pom.xml, golang->go.mod, pypi->requirements.txt, nuget->*.csproj. "
                "3. Read that file and confirm the affected package is declared as a DIRECT dependency. "
                f"{_TRANSITIVE_GUIDANCE} "
                "4. If it is direct, bump the version to the safe version and save the file. "
                "STOP after saving — do NOT run any shell or package manager command whatsoever "
                "(including npm install, npm install --package-lock-only, mvn install, "
                "go mod tidy, pip install, dotnet restore, or any variant). "
                "Leave lockfile regeneration to the user. "
            ),
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

    @mcp.tool()
    def get_latest_package_version(package_url: str) -> dict:
        """
        Query the internal Nexus Repository Manager for available versions of a
        package. Use this when recommendationMarkdown does not specify a fixed
        version — find the latest available version internally and use that.

        Requires NEXUS_REPO_BASE_URL to be set.

        Args:
            package_url: The purl from selected.packageUrl, e.g.:
                "pkg:npm/lodash@4.17.15"
                "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
                "pkg:pypi/requests@2.28.0"

        Returns:
            {
                "package": "lodash",
                "format": "npm",
                "versions": ["4.17.21", "4.17.20", ...],
                "latest": "4.17.21"
            }
        """
        if not _nexus_repo_client:
            raise RuntimeError(
                "NEXUS_REPO_BASE_URL is not set — cannot query Nexus Repository."
            )

        # Parse purl: pkg:format/[group/]name@version
        # Strip leading "pkg:" then split on "/" and "@"
        raw = package_url
        if raw.startswith("pkg:"):
            raw = raw[4:]
        purl_type, _, rest = raw.partition("/")
        purl_type = purl_type.lower()

        # Map purl type -> Nexus Repository format param
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

        # rest may be "group/name@version" or "name@version" (golang has long paths)
        name_part = rest.rsplit("/", 1)[-1]  # take last path segment
        name, _, _ = name_part.partition("@")

        resp = _nexus_repo_client.get(
            "/service/rest/v1/search",
            params={"format": fmt, "name": name, "sort": "version", "direction": "desc"},
        )
        if resp.status_code == 404 or resp.status_code == 400:
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

        return {
            "package": name,
            "format": fmt,
            "latest": versions[0],
            "versions": versions[:20],
        }
