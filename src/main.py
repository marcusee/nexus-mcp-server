import requests
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from packaging import version as pkg_version

class NexusClient:
    def __init__(self, base_url, auth=None):
        self.base_url = base_url.rstrip('/')
        self.auth = auth  # ("user", "pass") if needed

    def get_latest_version(self, name, fmt, group=None, allow_prerelease=False):
        """
        fmt: 'npm' | 'pypi' | 'maven2' | ...
        group: required for maven2 (groupId)
        """
        url = f"{self.base_url}/service/rest/v1/search"
        params = {
            "name": name,
            "format": fmt,
            "sort": "version",
            "direction": "desc",
        }
        if group:
            params["group"] = group

        versions = set()
        token = None
        while True:
            if token:
                params["continuationToken"] = token
            r = requests.get(url, params=params, auth=self.auth, timeout=30)
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

        # Use packaging.version for robust sorting (handles SemVer, PEP 440, most Maven)
        def parse(v):
            try:
                return pkg_version.parse(v)
            except Exception:
                return pkg_version.parse("0")

        sorted_versions = sorted(versions, key=parse, reverse=True)
        if not allow_prerelease:
            stable = [v for v in sorted_versions if not parse(v).is_prerelease]
            if stable:
                return stable[0]
        return sorted_versions[0]
Then parse each manifest into a common tuple shape (name, format, group):
pythondef parse_package_json(path):
    data = json.loads(Path(path).read_text())
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return [(name, "npm", None) for name in deps]

def parse_requirements_txt(path):
    out = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = re.split(r"[=<>!~;\[\s]", line, maxsplit=1)[0].strip()
        if name:
            out.append((name, "pypi", None))
    return out

def parse_pom_xml(path):
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    root = ET.parse(path).getroot()
    # Handle namespaced or non-namespaced POMs
    tag = lambda e, t: e.find(f"m:{t}", ns) if root.tag.startswith("{") else e.find(t)
    out = []
    deps = root.findall(".//m:dependency", ns) if root.tag.startswith("{") else root.findall(".//dependency")
    for d in deps:
        g, a = tag(d, "groupId"), tag(d, "artifactId")
        if g is not None and a is not None:
            out.append((a.text, "maven2", g.text))
    return out

PARSERS = {
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pom.xml": parse_pom_xml,
}

def parse_manifest(path):
    p = Path(path)
    parser = PARSERS.get(p.name)
    if not parser:
        raise ValueError(f"No parser for {p.name}")
    return parser(p)
Glue it together:
pythonif __name__ == "__main__":
    nexus = NexusClient("https://your-nexus")
    for name, fmt, group in parse_manifest("package.json"):
        latest = nexus.get_latest_version(name, fmt, group)
        print(f"{fmt}:{group+':' if group else ''}{name} -> {latest}")
A few things worth flagging:
Version sorting is the sneaky part. packaging.version handles PEP 440 and most SemVer cleanly, but Maven versions can be weird (1.0-RC1, 1.0.Final). If you hit Maven-heavy repos, swap in something like maven-artifact from the jip ecosystem, or roll your own comparator. Don't rely on Nexus's sort=version alone — it's a lexicographic sort server-side, which is why I re-sort client-side.
Scoped npm packages (@angular/core) — the name param in Nexus matches on the component name, which for npm includes the scope. Pass it as-is; no extra handling needed.
Maven without group — if you only have the artifactId, skip group and you'll get all matching artifacts across groups. Usually fine but can be ambiguous for common names.
Extending — for Gradle, go.mod, Cargo.toml, Gemfile.lock, etc., just add another parser that returns the same (name, format, group) tuple and register it in PARSERS. The Nexus client code doesn't change.
If your Nexus proxies public repos (which it usually does for this kind of scanning), this will give you the latest version that's actually available through your Nexus — which is the right answer for a vuln/dep scanner, since that's what your builds can actually resolve.You said: the thing is i am writing an mcp server fastify apithe thing is i am writing an mcp server fastify apiit will scan the dependency put and check if is the latest10:32 AMClaude responded: Got it — for an MCP server, you want clean tool boundaries and predictable JSON responses.Got it — for an MCP server, you want clean tool boundaries and predictable JSON responses. Here's how I'd structure it with FastMCP (the Python MCP SDK; "fastify" is a Node framework, but FastMCP is the closest Python equivalent and fits your existing code):
python# server.py
import json
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
async def scan_manifest(filename: str, content: str) -> dict:
    """Scan a dependency manifest and report outdated packages.

    Args:
        filename: The manifest filename (package.json, requirements.txt, pom.xml)
        content: The file contents as a string
    """
    try:
        deps = detect_and_parse(filename, content)
    except ValueError as e:
        return {"error": str(e)}

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


if __name__ == "__main__":
    mcp.run()