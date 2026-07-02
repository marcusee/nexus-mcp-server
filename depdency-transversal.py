def rollup_worst_cve(components: list[dict]) -> dict[str, float]:
    """purl -> worst CVSS among itself and everything beneath it. O(V+E)."""
    own = {}                      # purl -> worst own CVSS
    parents = defaultdict(list)   # purl -> parent purls
    for c in components:
        purl = c["packageUrl"]
        issues = (c.get("securityData") or {}).get("securityIssues") or []
        own[purl] = max((i.get("severity", 0.0) for i in issues), default=0.0)
        dd = c.get("dependencyData") or {}
        parents[purl] = dd.get("parentComponentPurls") or []

    # push each component's own score up to every ancestor, memoized
    best = dict(own)              # purl -> rolled-up worst
    def ancestors(purl, seen):
        for p in parents[purl]:
            if p in seen:         # DAG guard (npm dedupe can create diamonds)
                continue
            seen.add(p)
            if own.get(purl, 0.0) > best.get(p, 0.0) or True:
                best[p] = max(best.get(p, 0.0), best[purl_start])
            ancestors(p, seen)

    # simpler + correct: propagate every vulnerable node's score to all ancestors
    best = dict(own)
    for purl, score in own.items():
        if score == 0.0:
            continue
        stack, seen = list(parents[purl]), set()
        while stack:
            p = stack.pop()
            if p in seen:
                continue
            seen.add(p)
            if score > best.get(p, 0.0):
                best[p] = score
            stack.extend(parents.get(p, []))
    return best
