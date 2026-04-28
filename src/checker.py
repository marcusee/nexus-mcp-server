"""
Nexus IQ Version Checker - MCP Server (HTTP/SSE)
-------------------------------------------------
Exposes the Nexus IQ Advanced Search version check as an MCP tool over
HTTP/SSE transport.

Run:
    pip install "mcp[cli]" httpx
    python nexus_mcp_server.py

Default endpoint:
    http://0.0.0.0:8000/sse

Configuration is read from environment variables so secrets aren't baked
into the code:
    NEXUS_IQ_BASE_URL   (required, e.g. https://nexus-iq.mycompany.com)
    NEXUS_IQ_USERNAME   (optional)
    NEXUS_IQ_PASSWORD   (optional)
    NEXUS_IQ_VERIFY_SSL (optional, "false" to disable cert verification)
    MCP_HOST            (optional, default 0.0.0.0)
    MCP_PORT            (optional, default 8000)
"""

import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
NEXUS_IQ_BASE_URL = os.environ.get("NEXUS_IQ_BASE_URL", "").rstrip("/")
NEXUS_IQ_USERNAME = os.environ.get("NEXUS_IQ_USERNAME") or None
NEXUS_IQ_PASSWORD = os.environ.get("NEXUS_IQ_PASSWORD") or None
NEXUS_IQ_VERIFY_SSL = os.environ.get("NEXUS_IQ_VERIFY_SSL", "true").lower() != "false"

MCP_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("MCP_PORT", "8000"))


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="nexus-iq-version-checker",
    host=MCP_HOST,
    port=MCP_PORT,
)


# ---------------------------------------------------------------------------
# Core check (async, reused by the tool)
# ---------------------------------------------------------------------------
async def _check_library_version(
    library_name: str,
    version: str,
    page_size: int = 100,
    all_components: bool = True,
) -> dict[str, Any]:
    """
    Search Nexus IQ for componentName:{library_name}* and check whether
    any result has the requested version.

    Returns a structured dict so the MCP client gets context, not just
    a bare boolean.
    """
    if not NEXUS_IQ_BASE_URL:
        raise RuntimeError(
            "NEXUS_IQ_BASE_URL environment variable is not set."
        )

    query = f"componentName:{library_name}*"
    endpoint = f"{NEXUS_IQ_BASE_URL}/api/v2/search/advanced"
    auth = (
        (NEXUS_IQ_USERNAME, NEXUS_IQ_PASSWORD)
        if NEXUS_IQ_USERNAME and NEXUS_IQ_PASSWORD
        else None
    )

    target_version = version.strip()
    page = 0
    pages_scanned = 0
    items_scanned = 0
    matched_item: dict[str, Any] | None = None

    async with httpx.AsyncClient(
        auth=auth,
        headers={"Accept": "application/json"},
        verify=NEXUS_IQ_VERIFY_SSL,
        timeout=30.0,
    ) as client:
        while True:
            params = {
                "query": query,
                "page": page,
                "pageSize": page_size,
                "allComponents": str(all_components).lower(),
            }

            resp = await client.get(endpoint, params=params)

            if resp.status_code == 409:
                raise RuntimeError(
                    "Nexus IQ returned 409: Search index not found. "
                    "Re-indexing is required before Advanced Search "
                    "can return results."
                )
            resp.raise_for_status()
            data = resp.json()

            pages_scanned += 1

            for group in data.get("groupingByDTOS", []) or []:
                for item in group.get("searchResultItemDTOS", []) or []:
                    items_scanned += 1
                    if _item_matches(item, library_name, target_version):
                        matched_item = item
                        break
                if matched_item:
                    break
            if matched_item:
                break

            total_hits = data.get("totalNumberOfHits", 0) or 0
            if (page + 1) * page_size >= total_hits:
                break
            page += 1

    return {
        "matched": matched_item is not None,
        "library_name": library_name,
        "version": target_version,
        "pages_scanned": pages_scanned,
        "items_scanned": items_scanned,
        "match": _summarize_item(matched_item) if matched_item else None,
    }


def _item_matches(item: dict, library_name: str, target_version: str) -> bool:
    name = (item.get("componentName") or "").lower()
    if not name.startswith(library_name.lower()):
        return False

    coords = (item.get("componentIdentifier") or {}).get("coordinates") or {}
    found_version = coords.get("version")
    if found_version and found_version.strip() == target_version:
        return True

    # Fallback for ecosystems that key version differently.
    for value in coords.values():
        if isinstance(value, str) and value.strip() == target_version:
            return True

    return False


def _summarize_item(item: dict) -> dict[str, Any]:
    """Pull only the useful fields out of a search result for the response."""
    coords = (item.get("componentIdentifier") or {}).get("coordinates") or {}
    return {
        "componentName": item.get("componentName"),
        "applicationName": item.get("applicationName"),
        "applicationVersion": item.get("applicationVersion"),
        "organizationName": item.get("organizationName"),
        "reportId": item.get("reportId"),
        "policyEvaluationStage": item.get("policyEvaluationStage"),
        "coordinates": coords,
    }


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------
@mcp.tool()
async def check_library_version(library_name: str, version: str) -> dict[str, Any]:
    """
    Check whether a given library + version exists in any Nexus IQ scan.

    Performs an Advanced Search with a wildcard prefix match on the
    componentName (componentName:{library_name}*) and then verifies
    whether the requested version appears in any returned result.

    Args:
        library_name: The component/library name to search for.
                      A wildcard is appended automatically (e.g. "log4j"
                      matches "log4j-core", "log4j-api", ...).
        version:      The exact version string to look for.

    Returns:
        A dict with:
          - matched: bool, True if the version was found
          - library_name, version: echo of inputs
          - pages_scanned, items_scanned: how much of the index we walked
          - match: details of the matched scan (componentName, application,
                   organization, reportId, coordinates) or None
    """
    return await _check_library_version(library_name, version)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # FastMCP supports "sse" transport out of the box, which serves
    # /sse for the SSE stream and /messages/ for client posts.
    mcp.run(transport="sse")
