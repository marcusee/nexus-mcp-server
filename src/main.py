# server.py
import asyncio
import json
import os
import re
import time
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import httpx
from packaging import version as pkg_version
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("nexus-dep-scanner")

# ---------- Config ----------
NEXUS_BASE_URL = os.getenv("NEXUS_BASE_URL", "https://your-nexus")
NEXUS_AUTH = None  # ("user", "pass") if needed

ALLOWED_ROOTS = [os.path.expanduser("~"), "/workspace"]
SKIP_DIRS = {"node_modules", ".venv", "venv", ".git", "dist", "build", "target", "__pycache__"}
CONCURRENCY = 10
CACHE_TTL_SECONDS = 600  # 10 minutes

# ---------- Cache ----------
_cache: dict[tuple, tuple[float, Optional[str]]] = {}

def _cache_get(key):
    entry = _cache.get(key)
    if not entry:
        return None
    ts, val = entry
    if time.time() - ts > CACHE_TTL_SECONDS:
        _cache.pop(key, None)
        return None
    return val

def _cache_set(key, val):
    _cache[key] = (time.time(), val)

# ---------- Path safety ----------
def _is_path_allowed(path: Path) -> bool:
    resolved = path.resolve()
    return any(
        str(resolved).startswith(str(Path(root).resolve()))
        for root in ALLOWED_ROOTS
    )

# ---------- Nexus lookup ----------
async def fetch_latest_version(
    name: str,
    fmt: str,
    group: Optional[str] = None,
    allow_prerelease: bool = False,
    client: Optional[httpx.AsyncClient] = None,
) -> Optional[str]:
    cache_key = (name.lower(), fmt, (group or "").lower(), allow_prerelease)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    url = f"{NEXUS_BASE_URL}/service/rest/v1/search"
    params = {"name": name, "format": fmt, "sort": "version", "direction": "desc"}
    if group:
        params["group"] = group

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=30, auth=NEXUS_AUTH)

    versions = set()
    try:
        token = None
        while True:
            q = dict(params)
            if token:
                q["continuationToken"] = token
            r = await client.get(url, params=q)
            r.raise_for_status()
            data = r.json()
            for item in data.get("items", []):
                if item.get("version"):
                    versions.add(item["version"])
            token = data.get("continuationToken")
            if not token:
                break
    except Exception:
        if owns_client:
            await client.aclose()
        _cache_set(cache_key, None)
        return None
    finally:
        if owns_client:
            await client.aclose()

    if not versions:
        _cache_set(cache_key, None)
        return None

    def parse(v):
        try:
            return pkg_version.parse(v)
        except Exception:
            return pkg_version.parse("0")

    sorted_v = sorted(versions, key=parse, reverse=True)
    result = None
    if not allow_prerelease:
        stable = [v for v in sorted_v if not parse(v).is_prerelease]
        if stable:
            result = stable[0]
    if result is None:
        result = sorted_v[0]

    _cache_set(cache_key, result)
    return result

# ---------- Helpers ----------
def clean_version(v: str) -> str:
    """Strip specifiers like ^, ~, >=, == to get a plain version string."""
    return re.sub(r"^[\^~><=!\s]+", "", v).split(",")[0].strip()

def parse_pep508(spec: str):
    """Extract (name, version) from a PEP 508 dep string."""
    spec = spec.split(";", 1)[0].strip()   # drop env markers
    spec = spec.split("@", 1)[0].strip()   # drop URL/VCS specs
    if not spec:
        return None, ""
    m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)$", spec)
    if not m:
        return None, ""
    return m.group(1), clean_version(m.group(3) or "")

# ---------- Manifest parsers ----------
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
        name, current = parse_pep508(line)
        if name:
            out.append({"name": name, "format": "pypi", "group": None, "current": current})
    return out

def parse_pom_xml(content: str):
    root = ET.fromstring(content)
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    namespaced = root.tag.startswith("{")
    find = lambda el, t: el.find(f"m:{t}", ns) if namespaced else el.find(t)
    deps = (
        root.findall(".//m:dependency", ns) if namespaced
        else root.findall(".//dependency")
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

def parse_pyproject_toml(content: str):
    data = tomllib.loads(content)
    out = []
    seen = set()

    def add(name: str, version: str):
        key = name.lower()
        if name and key not in seen:
            seen.add(key)
            out.append({
                "name": name,
                "format": "pypi",
                "group": None,
                "current": clean_version(version or ""),
            })

    # PEP 621
    project = data.get("project", {})
    for dep in project.get("dependencies", []):
        name, current = parse_pep508(dep)
        if name:
            add(name, current)
    for _g, deps in project.get("optional-dependencies", {}).items():
        for dep in deps:
            name, current = parse_pep508(dep)
            if name:
                add(name, current)

    # Poetry
    poetry = data.get("tool", {}).get("poetry", {})
    for name, spec in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else (spec or {}).get("version", "")
        add(name, version)
    for _g, gdata in poetry.get("group", {}).items():
        for name, spec in (gdata or {}).get("dependencies", {}).items():
            version = spec if isinstance(spec, str) else (spec or {}).get("version", "")
            add(name, version)

    return out

PARSERS = {
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pom.xml": parse_pom_xml,
    "pyproject.toml": parse_pyproject_toml,
}
MANIFEST_NAMES = set(PARSERS.keys())

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

# ---------- Concurrent scan ----------
async def _scan_deps(deps: list[dict]) -> list[dict]:
    sem = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient(timeout=30, auth=NEXUS_AUTH) as client:
        async def one(dep):
            async with sem:
                latest = await fetch_latest_version(
                    dep["name"], dep["format"], dep["group"], client=client
                )
                return {**dep, "latest": latest, "status": compare(dep["current"], latest)}
        return await asyncio.gather(*(one(d) for d in deps))

def _summarize(results: list[dict]) -> dict:
    return {
        "total": len(results),
        "outdated": sum(1 for r in results if r["status"] == "outdated"),
        "up_to_date": sum(1 for r in results if r["status"] == "up_to_date"),
        "not_found": sum(1 for r in results if r["status"] == "not_found"),
        "ahead": sum(1 for r in results if r["status"] == "ahead"),
        "unknown": sum(1 for r in results if r["status"] == "unknown"),
    }

# ---------- MCP Tools ----------
@mcp.tool()
async def check_package(name: str, format: str, group: Optional[str] = None) -> dict:
    """Check the latest version of a single package in Nexus.

    Args:
        name: Package name (e.g., 'express', 'requests', 'fastmcp')
        format: One of 'npm', 'pypi', 'maven2'
        group: Maven groupId (required for maven2)
    """
    latest = await fetch_latest_version(name, format, group)
    return {"name": name, "format": format, "group": group, "latest": latest}

@mcp.tool()
async def scan_manifest(
    filename: Optional[str] = None,
    content: Optional[str] = None,
    path: Optional[str] = None,
) -> dict:
    """Scan a dependency manifest and report outdated packages.

    Provide either `content` (string) or `path` (file on disk).
    Supported manifests: package.json, requirements.txt, pom.xml, pyproject.toml.

    Args:
        filename: Manifest filename. Required if `content` is provided; derived from `path` otherwise.
        content: Raw file contents.
        path: Absolute path to the manifest file.
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

    if not filename:
        return {"error": "filename is required when passing 'content'"}

    try:
        deps = detect_and_parse(filename, content)
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"Failed to parse {filename}: {e}"}

    results = await _scan_deps(deps)
    return {
        "manifest": filename,
        "summary": _summarize(results),
        "dependencies": results,
    }

@mcp.tool()
async def scan_project(root: str, recursive: bool = True) -> dict:
    """Discover and scan all manifest files under a project directory.

    Args:
        root: Project root directory (absolute path).
        recursive: Search subdirectories. Skips node_modules, .venv, .git, etc.
    """
    root_path = Path(root)
    if not _is_path_allowed(root_path):
        return {"error": f"Path not in allowed roots: {root}"}
    if not root_path.is_dir():
        return {"error": f"Not a directory: {root}"}

    manifests: list[Path] = []
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