import asyncio
import csv
import httpx

BASE_URL = "https://iq.company.com"
AUTH = ("userCode", "passCode")


async def get_applications(client):
    """Get all applications."""
    r = await client.get(f"{BASE_URL}/api/v2/applications")
    r.raise_for_status()
    return r.json()["applications"]


async def get_latest_report(client, app_public_id):
    """Get latest report for an application."""
    r = await client.get(f"{BASE_URL}/api/v2/reports/applications/{app_public_id}")
    r.raise_for_status()
    reports = r.json()
    return reports[0] if reports else None


async def get_policy_violations(client, app_public_id, report_id):
    """Get policy violations from a report."""
    url = f"{BASE_URL}/api/v2/applications/{app_public_id}/reports/{report_id}/policy"
    r = await client.get(url)
    r.raise_for_status()
    return r.json()


async def get_vulnerability_details(client, ref_id, vuln_cache):
    """Get CVSS, exploitability for a CVE. Cached to avoid duplicate calls."""
    if ref_id in vuln_cache:
        return vuln_cache[ref_id]

    try:
        r = await client.get(
            f"{BASE_URL}/api/v2/vulnerabilities/{ref_id}",
            headers={"Accept": "application/json"},
        )
        r.raise_for_status()
        data = r.json()
        result = {
            "cvss_score": data.get("severityScores", [{}])[0].get("score", ""),
            "cvss_version": data.get("severityScores", [{}])[0].get("type", ""),
            "exploitability": data.get("mainSeverity", {}).get("source", ""),
        }
    except Exception:
        result = {"cvss_score": "", "cvss_version": "", "exploitability": ""}

    vuln_cache[ref_id] = result
    return result


async def get_remediation(client, app_internal_id, component_identifier, rem_cache):
    """Get the recommended remediation version for a component."""
    # Cache key based on the component coordinates
    coords = component_identifier.get("coordinates", {})
    cache_key = f"{app_internal_id}:{coords.get('groupId', '')}:{coords.get('artifactId', coords.get('packageId', ''))}:{coords.get('version', '')}"

    if cache_key in rem_cache:
        return rem_cache[cache_key]

    try:
        url = f"{BASE_URL}/api/v2/components/remediation/application/{app_internal_id}"
        r = await client.post(
            url,
            json={"componentIdentifier": component_identifier},
            headers={"Content-Type": "application/json"},
        )
        r.raise_for_status()
        data = r.json()

        # Look for the "next-no-violations" version (best fix)
        versions = data.get("remediation", {}).get("versionChanges", [])
        fix = ""
        for v in versions:
            if v.get("type") == "next-no-violations":
                fix = (
                    v.get("data", {})
                    .get("component", {})
                    .get("componentIdentifier", {})
                    .get("coordinates", {})
                    .get("version", "")
                )
                break
        # Fallback: any other suggested version
        if not fix and versions:
            fix = (
                versions[0]
                .get("data", {})
                .get("component", {})
                .get("componentIdentifier", {})
                .get("coordinates", {})
                .get("version", "")
            )
    except Exception:
        fix = ""

    rem_cache[cache_key] = fix
    return fix


async def process_application(client, app, semaphore, vuln_cache, rem_cache):
    """Get all violations + enrichment for one app."""
    async with semaphore:
        rows = []
        try:
            report = await get_latest_report(client, app["publicId"])
            if not report:
                return rows

            report_id = report["reportDataUrl"].split("/")[-2]
            policy_data = await get_policy_violations(client, app["publicId"], report_id)

            for component in policy_data.get("components", []):
                lib_name = component.get("displayName", "")
                comp_id = component.get("componentIdentifier", {})
                coords = comp_id.get("coordinates", {})
                version = coords.get("version", "")

                # Get remediation once per component (not per violation)
                remediation = await get_remediation(
                    client, app["id"], comp_id, rem_cache
                )

                for violation in component.get("violations", []):
                    conditions = violation.get("constraints", [{}])[0].get("conditions", [])
                    # Find CVE reference
                    cve = ""
                    ref_id = ""
                    for c in conditions:
                        reason = c.get("conditionReason", "")
                        if "CVE" in reason or "sonatype" in reason.lower():
                            cve = reason
                            ref_id = reason
                            break

                    # Enrich with CVSS / exploitability
                    vuln_details = (
                        await get_vulnerability_details(client, ref_id, vuln_cache)
                        if ref_id
                        else {"cvss_score": "", "cvss_version": "", "exploitability": ""}
                    )

                    rows.append({
                        "Application": app["name"],
                        "Library": lib_name,
                        "Version": version,
                        "CVE ID": cve,
                        "Severity": violation.get("policyThreatLevel", ""),
                        "CVSS Score": vuln_details["cvss_score"],
                        "CVSS Version": vuln_details["cvss_version"],
                        "Exploitability": vuln_details["exploitability"],
                        "Policy": violation.get("policyName", ""),
                        "Status": "Waived" if violation.get("waived") else "Open",
                        "Remediation Version": remediation,
                    })
        except Exception as e:
            print(f"  ⚠️  Error on {app['name']}: {e}")

        print(f"  ✓ {app['name']}: {len(rows)} violations")
        return rows


async def main():
    semaphore = asyncio.Semaphore(10)
    vuln_cache = {}  # avoid duplicate CVE lookups
    rem_cache = {}   # avoid duplicate remediation lookups

    async with httpx.AsyncClient(auth=AUTH, timeout=60.0) as client:
        print("Fetching applications...")
        apps = await get_applications(client)
        print(f"Found {len(apps)} applications\n")

        print("Fetching violations + enrichment for each app...")
        results = await asyncio.gather(
            *[process_application(client, app, semaphore, vuln_cache, rem_cache)
              for app in apps]
        )

    all_rows = [row for app_rows in results for row in app_rows]
    print(f"\nTotal violations: {len(all_rows)}")
    print(f"Unique CVEs looked up: {len(vuln_cache)}")
    print(f"Unique remediations looked up: {len(rem_cache)}")

    if all_rows:
        with open("vulnerabilities.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
            writer.writeheader()
            writer.writerows(all_rows)
        print("✅ Saved to vulnerabilities.csv")


asyncio.run(main())