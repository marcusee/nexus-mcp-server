"""
Nexus IQ Advanced Search - Version Match Checker (httpx)
---------------------------------------------------------
Calls /api/v2/search/advanced with a wildcard componentName query
(componentName=name*), then walks the response to see whether the
given version exists for that library.
 
Returns True if a match is found, False otherwise.
"""
 
import httpx
 
 
def check_library_version(
    base_url: str,
    library_name: str,
    version: str,
    username: str | None = None,
    password: str | None = None,
    page_size: int = 100,
    all_components: bool = True,
    verify_ssl: bool = True,
    timeout: float = 30.0,
) -> bool:
    """
    Check whether a given library + version combination exists in Nexus IQ
    via the Advanced Search API.
 
    Args:
        base_url: Nexus IQ root URL, e.g. "https://nexus-iq.mycompany.com"
        library_name: The component/library name to search for (wildcard appended).
        version: The version string to look for in the search results.
        username, password: Basic auth credentials (optional).
        page_size: Results per page (paginates through all pages).
        all_components: If True, include components without violations.
        verify_ssl: Set False only if your Nexus IQ uses a self-signed cert.
        timeout: Per-request timeout in seconds.
 
    Returns:
        True if any result matches both the library name and the version,
        False otherwise.
    """
    # Build wildcard query: componentName:name*
    query = f"componentName:{library_name}*"
 
    endpoint = f"{base_url.rstrip('/')}/api/v2/search/advanced"
 
    auth = (username, password) if username and password else None
    headers = {"Accept": "application/json"}
 
    target_version = version.strip()
    page = 0
 
    with httpx.Client(
        auth=auth,
        headers=headers,
        verify=verify_ssl,
        timeout=timeout,
    ) as client:
        while True:
            params = {
                "query": query,
                "page": page,
                "pageSize": page_size,
                "allComponents": str(all_components).lower(),
            }
 
            resp = client.get(endpoint, params=params)
 
            if resp.status_code == 409:
                raise RuntimeError(
                    "Search index not found (409). Re-indexing is required "
                    "before the Advanced Search API can return results."
                )
            resp.raise_for_status()
 
            data = resp.json()
 
            # Walk the grouped results -> searchResultItemDTOS
            for group in data.get("groupingByDTOS", []) or []:
                for item in group.get("searchResultItemDTOS", []) or []:
                    if _item_matches(item, library_name, target_version):
                        return True
 
            # Pagination: stop once we've consumed all results
            total_hits = data.get("totalNumberOfHits", 0) or 0
            seen_so_far = (page + 1) * page_size
            if seen_so_far >= total_hits:
                break
            page += 1
 
    return False
 
 
def _item_matches(item: dict, library_name: str, target_version: str) -> bool:
    """
    Decide whether a single searchResultItemDTO matches the requested
    library name (prefix match, case-insensitive) and exact version.
    """
    name = (item.get("componentName") or "").lower()
    if not name.startswith(library_name.lower()):
        # Defensive: server should have filtered by query, but double-check.
        return False
 
    # Version lives inside componentIdentifier.coordinates.
    coords = (
        (item.get("componentIdentifier") or {}).get("coordinates") or {}
    )
    found_version = coords.get("version")
    if found_version and found_version.strip() == target_version:
        return True
 
    # Fallback: scan all coordinate values in case the version key is named
    # differently for some ecosystems.
    for value in coords.values():
        if isinstance(value, str) and value.strip() == target_version:
            return True
 
    return False
 
 
# ---------------------------------------------------------------------------
# Optional async variant — useful if you'll be calling this inside FastAPI
# or alongside other async I/O.
# ---------------------------------------------------------------------------
async def check_library_version_async(
    base_url: str,
    library_name: str,
    version: str,
    username: str | None = None,
    password: str | None = None,
    page_size: int = 100,
    all_components: bool = True,
    verify_ssl: bool = True,
    timeout: float = 30.0,
) -> bool:
    query = f"componentName:{library_name}*"
    endpoint = f"{base_url.rstrip('/')}/api/v2/search/advanced"
    auth = (username, password) if username and password else None
    headers = {"Accept": "application/json"}
    target_version = version.strip()
    page = 0
 
    async with httpx.AsyncClient(
        auth=auth,
        headers=headers,
        verify=verify_ssl,
        timeout=timeout,
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
                    "Search index not found (409). Re-indexing is required "
                    "before the Advanced Search API can return results."
                )
            resp.raise_for_status()
 
            data = resp.json()
            for group in data.get("groupingByDTOS", []) or []:
                for item in group.get("searchResultItemDTOS", []) or []:
                    if _item_matches(item, library_name, target_version):
                        return True
 
            total_hits = data.get("totalNumberOfHits", 0) or 0
            if (page + 1) * page_size >= total_hits:
                break
            page += 1
 
    return False
 
 
# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    BASE_URL = "https://nexus-iq.example.com"
    USERNAME = "your-username"
    PASSWORD = "your-password"
 
    # The two inputs:
    LIBRARY_NAME = "log4j-core"   # input 1
    VERSION = "2.14.1"            # input 2
 
    found = check_library_version(
        base_url=BASE_URL,
        library_name=LIBRARY_NAME,
        version=VERSION,
        username=USERNAME,
        password=PASSWORD,
    )
 
    print(f"Match for {LIBRARY_NAME} @ {VERSION}: {found}")
