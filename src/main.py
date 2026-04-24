# server.py
import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional
import httpx
from packaging import version as pkg_version
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("nexus-dep-scanner")

NEXUS_BASE_URL = "https://your-nexus"
NEXUS_AUTH = None  # ("user", "pass") if needed


# ---------- Nexus lookup ----------
async def fetch_latest_version(
    name: str, fmt: str, group: Optional[str] = None, allow_prerelease: bool = False
) -> Optional[str]:
    url = f"{NEXUS_BASE_URL}/service/rest/v1/search"
    params = {"name": name, "format": fmt, "sort": "version", "direction": "desc"}
    if group:
        params["group"] = group

    versions = set()
    token = None
    async with httpx.AsyncClient(timeout=30, auth=NEXUS_AUTH) as client:
        while True:
            if token:
                params["continuationToken"] = token
            r = await client.get(url, params=params)
            r.raise_for_status()
            data = r.json()
            for item in data.get("items", []):
                if item.get("version"):
                    versions.add(item["version"])
            token = data.get("continuationToken")
            if not token:
                break

    if not versions:
        return None

    def parse(v):
        try:
            return pkg_version.parse(v)
        except Exception:
            return pkg_version.parse("0")

    sorted_v = sorted(versions, key=parse, reverse=True)
    if not allow_prerelease:
        stable = [v for v in sorted_v if not parse(v).is_prerelease]
        if stable:
            return stable[0]
    return sorted_v[0]


# ---------- Manifest parsers ----------
def clean_version(v: str) -> str:
    """Strip npm/pip version specifiers to get a plain version string."""
    return re.sub(r"^[\^~><=!\s]+", "", v).split(",")[0].strip()


def parse_package_json(content: str):
    data = json.loads(content)
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return [
        {"name": n, "format": "npm", "group": None, "current": clean_version(v)}
        for n, v in deps.items()
    ]


def parse_requirements_txt(content: str):
    out = []
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([=<>!~].*)?$", line)
        if not m:
            continue
        name = re.split(r"\[", m.group(1))[0]
        current = clean_version(m.group(2) or "")
        out.append({"name": name, "format": "pypi", "group": None, "current": current})
    return out


def parse_pom_xml(content: str):
    root = ET.fromstring(content)
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    namespaced = root.tag.startswith("{")
    find = lambda el, t: el.find(f"m:{t}", ns) if namespaced else el.find(t)
    deps = (
        root.findall(".//m:dependency", ns) if namespaced else root.findall(".//dependency")
    )
    out = []
    for d in deps:
        g, a, v = find(d, "groupId"), find(d, "artifactId"), find(d, "version")
        if g is not None and a is not None:
            out.append({
                "name": a.text,
                "format": "maven2",
                "group": g.text,
                "current": v.text if v is not None else "",
            })
    return out


PARSERS = {
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pom.xml": parse_pom_xml,
}


def detect_and_parse(filename: str, content: str):
    parser = PARSERS.get(Path(filename).name)
    if not parser:
        raise ValueError(f"Unsupported manifest: {filename}")
    return parser(content)


# ---------- Version comparison ----------
def compare(current: str, latest: Optional[str]) -> str:
    if not latest:
        return "not_found"
    if not current:
        return "unknown"
    try:
        c, l = pkg_version.parse(current), pkg_version.parse(latest)
        if c == l:
            return "up_to_date"
        return "outdated" if c < l else "ahead"
    except Exception:
        return "up_to_date" if current == latest else "unknown"


# Optional: restrict which directories can be scanned
ALLOWED_ROOTS = [os.path.expanduser("~"), "/workspace"]  # adjust as needed

def _is_path_allowed(path: Path) -> bool:
    resolved = path.resolve()
    return any(
        str(resolved).startswith(str(Path(root).resolve()))
        for root in ALLOWED_ROOTS
    )

MANIFEST_NAMES = set(PARSERS.keys())  # {"package.json", "requirements.txt", "pom.xml"}

# ---------- MCP Tools ----------
@mcp.tool()
async def check_package(name: str, format: str, group: Optional[str] = None) -> dict:
    """Check the latest version of a single package in Nexus.

    Args:
        name: Package name (e.g., 'express', 'requests')
        format: One of 'npm', 'pypi', 'maven2'
        group: Maven groupId (required for maven2)
    """
    latest = await fetch_latest_version(name, format, group)
    return {"name": name, "format": format, "group": group, "latest": latest}


@mcp.tool()
async def scan_manifest(
    filename: str,
    content: Optional[str] = None,
    path: Optional[str] = None,
) -> dict:
    """Scan a dependency manifest. Provide either `content` (string) or `path` (file on disk).

    Args:
        filename: Manifest filename (package.json, requirements.txt, pom.xml).
                  Used to pick the parser. If `path` is given, this can be derived from it.
        content: Raw file contents. Use this when the client has already read the file.
        path: Absolute path to the manifest file. Use this when the server has FS access.
    """
    if content is None and path is None:
        return {"error": "Provide either 'content' or 'path'"}

    if path:
        p = Path(path)
        if not _is_path_allowed(p):
            return {"error": f"Path not in allowed roots: {path}"}
        if not p.exists():
            return {"error": f"File not found: {path}"}
        content = p.read_text(encoding="utf-8")
        filename = filename or p.name

    try:
        deps = detect_and_parse(filename, content)
    except ValueError as e:
        return {"error": str(e)}

    # ... rest of the function stays the same (fetch latest, build summary)
    results = []
    for dep in deps:
        latest = await fetch_latest_version(dep["name"], dep["format"], dep["group"])
        results.append({
            **dep,
            "latest": latest,
            "status": compare(dep["current"], latest),
        })
    summary = {
        "total": len(results),
        "outdated": sum(1 for r in results if r["status"] == "outdated"),
        "up_to_date": sum(1 for r in results if r["status"] == "up_to_date"),
        "not_found": sum(1 for r in results if r["status"] == "not_found"),
    }
    return {"manifest": filename, "summary": summary, "dependencies": results}



@mcp.tool()
async def scan_project(root: str, recursive: bool = True) -> dict:
    """Discover and scan all manifest files in a project directory.

    Walks the directory, finds package.json / requirements.txt / pom.xml,
    and scans each one.

    Args:
        root: Project root directory (absolute path).
        recursive: Whether to search subdirectories. Skips node_modules/.venv/etc.
    """
    root_path = Path(root)
    if not _is_path_allowed(root_path):
        return {"error": f"Path not in allowed roots: {root}"}
    if not root_path.is_dir():
        return {"error": f"Not a directory: {root}"}

    SKIP_DIRS = {"node_modules", ".venv", "venv", ".git", "dist", "build", "target"}
    manifests = []

    if recursive:
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if fn in MANIFEST_NAMES:
                    manifests.append(Path(dirpath) / fn)
    else:
        manifests = [root_path / n for n in MANIFEST_NAMES if (root_path / n).exists()]

    if not manifests:
        return {"root": str(root_path), "manifests": [], "message": "No manifests found"}

    scans = []
    for m in manifests:
        result = await scan_manifest(filename=m.name, path=str(m))
        result["path"] = str(m)
        scans.append(result)

    return {
        "root": str(root_path),
        "manifests_found": len(manifests),
        "scans": scans,
    }

if __name__ == "__main__":
    mcp.run()