# northfield-attack-path

Single-story attack path viewer for Northfield — served via GitHub Pages,
opened as a plain link from a Kibana dashboard.

## What this shows

Only the **latest** analysis the agent has written — nothing accumulated,
nothing historical, no merged "full environment" view. Open the page, see
this run's story:

- **A clear start** — identity + machine together (e.g. `lopezvictor` on
  `NFLD-SLS-LT-006`), not just a bare hostname.
- **A linear chain, left to right** — entry → pivot → pivot → target, in the
  actual order the analysis describes. Not a force-directed graph; an
  attack path is a sequence, so it reads like one.
- **Real enrichment on every node** — owner, department, IP, and top CVEs,
  pulled live from `northfield-cmdb` and `northfield-qualys-vulnerabilities`.
  (Note: CMDB doesn't track IP at all — that field comes from Qualys only,
  matched by hostname.)
- **"Game over" collapsing** — once the chain reaches a domain controller or
  a critical SQL/DB server, the graph stops enumerating what's technically
  reachable next and shows one terminal "Full domain compromise" state
  instead. Past that point, the specific list stops being the useful fact.
- **Blast radius**, shown separately and visually quieter (dashed chips),
  only when the chain does NOT reach a game-over node — it's an explicitly
  different claim ("reachable, not confirmed") from the solid chain above it.

## Setup

### 1. Deploy the Worker

```bash
npm install -g wrangler   # or use the ~/.npm-global prefix approach if you hit EACCES
wrangler login
wrangler secret put ES_URL        # e.g. https://<project>.es.<region>.gcp.elastic.cloud
wrangler secret put ES_API_KEY
wrangler deploy
```

### 2. Point the page at it

Edit `index.html`, set:
```js
const WORKER_URL = 'https://northfield-attack-path-proxy.<your-subdomain>.workers.dev';
```

Also check `ALLOWED_ORIGIN` in `worker.js` matches this repo's actual GitHub
Pages URL.

### 3. Push

```bash
git add index.html worker.js wrangler.toml
git commit -m "..."
git push
```

GitHub Pages redeploys automatically.

## The three document shapes this reads (priority order)

1. **Structured summary** (`document_type: 'attack_path_summary'`) — richest
   signal: explicit ordered `attack_phases`, named `most_at_risk_user`,
   structured `blast_radius`. Used whenever present.
2. **Free-text narrative** (`message` field) — either the older
   `--- ATTACK PATH N ---` delimiter style or real markdown (`## Header`,
   `### Node N`). Parsed into an approximate chain from node order.
3. **Raw CMDB-graph edges** (`graph.type` nested, self-describing
   source/target) — last resort if neither of the above exists.

## If the workflow's output shape changes again

It's LLM-generated, so this is possible. If the graph comes back thin or
wrong after a fresh write, pull the actual document from
`northfield-attack-graph` in Discover and extend the relevant parser in
`worker.js` (`parseMetaSummaryToGraph` / `parseNarrativeToGraph` /
`parseCmdbGraphDocs`) against the real shape — same pattern used to build
every format this already handles.

## Enrichment field reference (confirmed, not guessed)

- **CMDB** (`northfield-cmdb`): `asset.hostname`, `asset.criticality`,
  `asset.type`, `northfield.cmdb.owner_username`, `organization.department`,
  `northfield.cmdb.monitoring_status`
- **Qualys** (`northfield-qualys-vulnerabilities`): `host.name`, `host.ip[]`,
  `vulnerability.id`, `vulnerability.cvss.v3_1.base_score`,
  `vulnerability.severity`, `qualys.vulnerability.patch_available`,
  `qualys.vulnerability.times_found`
