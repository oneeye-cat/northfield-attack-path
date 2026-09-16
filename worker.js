// narrative-parser.js
//
// The real northfield-attack-graph index doesn't contain the {type:'node'},
// {type:'edge'} documents the graph UI was originally built to expect — it
// contains a single free-text narrative document per run (source:
// 'ai-analysis'), written by whatever agent currently generates the attack
// path analysis. This module bridges that gap: it extracts a graph from the
// text (so the D3 visualization still has something to draw) and reflows
// the text into markdown-ish structure the existing narrative renderer
// already knows how to style.
//
// This is a heuristic text parser, not a strict schema — it's built against
// the actual sample narrative format (section headers like
// "--- ATTACK PATH N: Title ---", "Entry:"/"Path:"/"Path Node:"/"Target:"
// lines, NFLD-* hostnames, MITRE technique ids). If the agent's output
// format drifts, this may need re-tuning, but it degrades gracefully —
// worst case a section contributes no graph edges rather than crashing.

const HOSTNAME_RE = /NFLD-[A-Z0-9]+(?:-[A-Z0-9]+)*/g;

// Narrative text uses shorthand like "NFLD-FIN-SRV01/02" or "NFLD-APP01/02/03"
// to mean multiple hosts sharing a prefix. Left as-is, HOSTNAME_RE only
// catches the first ("NFLD-FIN-SRV01"), silently dropping "/02" — which then
// breaks later host-set comparisons (a fully-spelled-out line elsewhere
// listing the same hosts no longer looks identical). Expand this shorthand
// into full hostnames before any extraction happens.
function expandShorthandHostnames(text) {
  return text.replace(/\b(NFLD-[A-Z]+(?:-[A-Z]+)*)(\d+)((?:\/\d+)+)/g, (full, prefix, firstNum, rest) => {
    const nums = [firstNum, ...rest.split('/').filter(Boolean)];
    return nums.map(n => `${prefix}${n}`).join(' ');
  });
}

function classifyNodeType(hostname) {
  if (/DC\d*$/.test(hostname)) return 'domain_controller';
  if (/(SQL|MAIL|APP|SRV|MGMT|BUILD|GIT|VPN)\d*/.test(hostname)) return 'server';
  if (/(WS|LT)-?\d*/.test(hostname)) return 'workstation';
  return 'server';
}

function classifyEdgeType(title, body) {
  const t = title.toLowerCase();
  // Prefer the section's own title — it names the attack pattern directly
  // ("Takeover", "Exfiltration", "Credential Stuffing") — over scanning the
  // body for MITRE technique ids, which often co-occur across categories
  // (e.g. T1003 credential dumping appears inside a "Takeover" path) and
  // would otherwise mask the more specific, human-labeled intent.
  if (t.includes('exfil')) return 'exfiltration';
  if (t.includes('credential')) return 'credential_access';
  if (t.includes('lateral') || t.includes('takeover')) return 'lateral_movement';
  const b = body.toLowerCase();
  if (b.includes('exfil')) return 'exfiltration';
  if (/t1110|t1003|t1552/.test(b)) return 'credential_access';
  if (/t1021|t1078/.test(b)) return 'lateral_movement';
  return 'data_access';
}

// Extracts a criticality hint for a host from its surrounding text —
// looks for an explicit "(...Critical...)" annotation near the hostname,
// otherwise falls back to type-based defaults.
function inferCriticality(hostname, fullText) {
  const idx = fullText.indexOf(hostname);
  if (idx >= 0) {
    const window = fullText.slice(idx, idx + 80);
    if (/critical/i.test(window)) return 'critical';
  }
  const type = classifyNodeType(hostname);
  if (type === 'domain_controller') return 'critical';
  if (type === 'server') return 'high';
  return 'medium';
}

// Splits the narrative into "--- SECTION TITLE ---" blocks.
function splitSections(text) {
  const parts = text.split(/^---\s*(.+?)\s*---\s*$/m);
  // parts alternates: [preamble, title1, body1, title2, body2, ...]
  const sections = [];
  for (let i = 1; i < parts.length; i += 2) {
    sections.push({ title: parts[i].trim(), body: parts[i + 1] || '' });
  }
  return { preamble: parts[0] || '', sections };
}

// ── Format detection ────────────────────────────────────────────────────
// Two known shapes of narrative document exist in the wild:
//  - "delimiter" style: "--- ATTACK PATH N: Title ---" section markers,
//    Entry:/Path:/Target: labeled lines. Multiple parallel numbered paths
//    in one document.
//  - "markdown" style: real "## Header" / "### Node N — ..." headers and
//    real "| a | b |" tables — what the attack-path-investigator agent's
//    system prompt actually mandates. One linear Entry→Node→Node chain per
//    document, answering one specific question, plus a "Possible Targets"
//    blast-radius table.
function isMarkdownFormat(text) {
  return /^#{1,3}\s/m.test(text) || /^\|.+\|.*\|\s*$/m.test(text);
}

// ── "delimiter" style parser (--- ATTACK PATH N: Title ---) ────────────
// Builds { nodes, edges } from ATTACK PATH sections specifically — those are
// the only sections with an Entry → Path → Target chain worth graphing.
// Other sections (UTM detections, escalation contacts, remediation) feed the
// narrative panel but aren't graph-worthy.
function parseDelimiterStyleToGraph(rawText) {
  const fullText = expandShorthandHostnames(rawText);
  const { sections } = splitSections(fullText);
  const nodes = new Map(); // node_id -> node
  const edges = [];

  const addNode = (hostname, criticalityHint) => {
    if (nodes.has(hostname)) return;
    nodes.set(hostname, {
      type: 'node',
      node_id: hostname,
      label: hostname,
      node_type: classifyNodeType(hostname),
      criticality: criticalityHint || inferCriticality(hostname, fullText),
    });
  };

  sections
    .filter(s => /^ATTACK PATH \d+/i.test(s.title))
    .forEach(s => {
      const edgeType = classifyEdgeType(s.title, s.body);

      // This narrative format uses arrows (→ or ->) to encode the actual
      // step order, both within a single line ("Path: A → B → C") and
      // conceptually across the Entry/Path Node/Path/Target lines. Splitting
      // only on line boundaries (ignoring in-line arrows) would flatten a
      // multi-hop line into one undifferentiated group and produce
      // duplicate/backwards edges once combined with neighboring lines — so
      // pull out each line's content, join them in label order with an
      // arrow, then split the *combined* route on arrows to get real steps.
      const labeledLines = [];
      const lineRe = /^(Entry|Path Node|Path|Target):\s*(.+)$/gim;
      let m;
      while ((m = lineRe.exec(s.body))) labeledLines.push(m[2]);
      if (!labeledLines.length) return;

      const routeSegments = labeledLines.join(' → ').split(/→|->/);
      let chain = routeSegments
        .map(seg => [...new Set(seg.match(HOSTNAME_RE) || [])])
        .filter(group => group.length); // drop segments with no hostnames (e.g. "credential harvest")

      // Collapse consecutive steps that name the exact same host set — this
      // narrative format sometimes restates the prior step's hosts verbatim
      // in a following "Target:" line rather than introducing a new step
      // (e.g. "...→ FIN-SRV01/02 / SQL02 / DC01" followed by a separate
      // "Target: FIN-SRV01, FIN-SRV02, SQL02, DC01" line). Without this,
      // those hosts get cross-connected to each other as if the path forked
      // through itself.
      const setKey = g => [...g].sort().join(',');
      chain = chain.filter((g, i) => i === 0 || setKey(g) !== setKey(chain[i - 1]));

      chain.forEach(hostGroup => hostGroup.forEach(h => addNode(h)));

      // Connect each step's hosts to the next step's hosts (fan-out/fan-in
      // if a step has multiple hosts — e.g. 3 app servers all leading to
      // one SQL target).
      for (let i = 0; i < chain.length - 1; i++) {
        chain[i].forEach(src => {
          chain[i + 1].forEach(dst => {
            if (src !== dst) edges.push({ type: 'edge', source_id: src, target_id: dst, edge_type: edgeType });
          });
        });
      }
    });

  return { nodes: [...nodes.values()], edges };
}

// ── "markdown" style parser (## Header, ### Node N — ..., real tables) ──
// This is the shape the attack-path-investigator agent's system prompt
// actually mandates: one linear Entry → Node 1 → Node 2 → ... chain (the
// "## Attack Path" section, one "### Node N — ..." block per hop, each with
// a "**HOST:** <hostname>" line), then a "## Possible Targets (Blast
// Radius)" table fanning out from the final node — each row's first column
// names a target, its last column ("How Reachable") hints at the edge type.
function splitMarkdownSections(text) {
  const headerRe = /^##\s+(.+)$/gm;
  const matches = [...text.matchAll(headerRe)];
  return matches.map((m, i) => ({
    title: m[1].trim(),
    body: text.slice(m.index + m[0].length, i + 1 < matches.length ? matches[i + 1].index : text.length),
  }));
}

function parseMarkdownRow(line) {
  const trimmed = line.trim();
  if (!/^\|.*\|$/.test(trimmed)) return null;
  if (/^\|[\s\-:|]+\|$/.test(trimmed)) return null; // separator row (|---|---|)
  return trimmed.slice(1, -1).split('|').map(c => c.trim());
}

function parseMarkdownAnalysisToGraph(rawText) {
  const text = expandShorthandHostnames(rawText);
  const nodes = new Map();
  const edges = [];
  const addNode = (hostname, criticalityHint) => {
    if (nodes.has(hostname)) {
      if (criticalityHint) nodes.get(hostname).criticality = criticalityHint;
      return;
    }
    nodes.set(hostname, {
      type: 'node', node_id: hostname, label: hostname,
      node_type: classifyNodeType(hostname),
      criticality: criticalityHint || inferCriticality(hostname, text),
    });
  };
  const parseCriticality = (str) => {
    const c = (str || '').toLowerCase();
    if (c.includes('critical')) return 'critical';
    if (c.includes('high')) return 'high';
    if (c.includes('medium')) return 'medium';
    if (c.includes('low')) return 'low';
    return null;
  };

  const sections = splitMarkdownSections(text);
  const entrySection = sections.find(s => /entry point/i.test(s.title));
  const attackPathSection = sections.find(s => /^attack path$/i.test(s.title.trim()) || (/attack path/i.test(s.title) && !/summary/i.test(s.title)));
  const targetsSection = sections.find(s => /possible target|blast radius/i.test(s.title));

  // Overall edge type for the main chain — inferred from the entry point's
  // stated tactic/vector, since this format has one chain per document
  // rather than a per-path title like the delimiter style does.
  const scanText = (entrySection?.body || '') + ' ' + (attackPathSection?.body?.slice(0, 500) || '');
  const chainEdgeType = classifyEdgeType(scanText, scanText);

  const chain = [];
  if (attackPathSection) {
    const nodeHeaderRe = /^###\s+(.+)$/gm;
    const headerMatches = [...attackPathSection.body.matchAll(nodeHeaderRe)];
    headerMatches.forEach((h, i) => {
      const block = attackPathSection.body.slice(
        h.index + h[0].length,
        i + 1 < headerMatches.length ? headerMatches[i + 1].index : attackPathSection.body.length
      );
      const hostLineMatch = block.match(/\*\*HOST:?\*\*\s*(NFLD-[A-Z0-9-]+)/i);
      // When there's no explicit **HOST:** line, prefer the node's blockquote
      // transition line ("> A or B → THIS_NODE") specifically, taking its
      // LAST hostname — that's the destination of the hop, not the source it
      // pivoted from. Scanning the *whole* block (including trailing bullet
      // notes) instead can pick up an unrelated hostname mentioned further
      // down (e.g. a "reachable from here" aside), which isn't this node's
      // actual identity. Only fall back to whole-block scanning if the
      // transition line itself has no hostname at all.
      const quoteLine = block.split('\n').find(l => /^\s*>/.test(l));
      const quoteHosts = quoteLine ? quoteLine.match(HOSTNAME_RE) : null;
      const allHostMatches = quoteHosts || block.match(HOSTNAME_RE);
      const hostname = hostLineMatch ? hostLineMatch[1] : (allHostMatches ? allHostMatches[allHostMatches.length - 1] : null);
      if (!hostname) return;
      const critMatch = block.match(/\*\*Asset criticality:?\*\*\s*([^\n|]+)/i);
      const crit = critMatch ? parseCriticality(critMatch[1]) : null;
      addNode(hostname, crit);
      chain.push(hostname);
    });
  }

  for (let i = 0; i < chain.length - 1; i++) {
    if (chain[i] !== chain[i + 1]) {
      edges.push({ type: 'edge', source_id: chain[i], target_id: chain[i + 1], edge_type: chainEdgeType });
    }
  }

  if (targetsSection && chain.length) {
    const lastNode = chain[chain.length - 1];
    // Exclude the WHOLE chain, not just the last node — a target already
    // visited as an earlier hop (e.g. the Finance SQL server that was step 3
    // of 5) shouldn't get a new "blast radius" edge drawn backward into it
    // from the final node; it's already connected via the real path.
    const chainSet = new Set(chain);
    targetsSection.body.split('\n').forEach(line => {
      const cells = parseMarkdownRow(line);
      if (!cells || cells.length < 2) return;
      if (/^\*{0,2}target\*{0,2}$/i.test(cells[0].trim())) return; // header row itself
      const hosts = [...new Set(cells[0].match(HOSTNAME_RE) || [])];
      if (!hosts.length) return;
      const reachText = cells[cells.length - 1] || '';
      const edgeType = classifyEdgeType(reachText, reachText);
      hosts.forEach(h => {
        addNode(h);
        if (!chainSet.has(h)) edges.push({ type: 'edge', source_id: lastNode, target_id: h, edge_type: edgeType });
      });
    });
  }

  return { nodes: [...nodes.values()], edges };
}

// ── Dispatcher — tries the right parser for whichever format this
// particular document turns out to be, falling back gracefully to an empty
// graph (never throws) if neither recognizes it.
function parseNarrativeToGraph(rawText) {
  try {
    if (isMarkdownFormat(rawText)) {
      const g = parseMarkdownAnalysisToGraph(rawText);
      if (g.nodes.length) return g;
    }
    return parseDelimiterStyleToGraph(rawText);
  } catch (e) {
    return { nodes: [], edges: [] };
  }
}

// Reflows the narrative's own section-header style ("--- X ---") and plain
// lines into the markdown-ish syntax the existing client-side renderer
// (renderNarrative() in attack-graph.html) already knows how to convert to
// styled HTML — headers, bullet lines, paragraph breaks.
function narrativeMessageToMarkdown(message) {
  const lines = message.split('\n');
  const out = [];
  let firstLine = true;
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (firstLine && line.trim()) {
      out.push(`# ${line.trim()}`);
      firstLine = false;
      continue;
    }
    const sectionMatch = line.match(/^---\s*(.+?)\s*---\s*$/);
    if (sectionMatch) {
      out.push('');
      out.push(`## ${sectionMatch[1].trim()}`);
      continue;
    }
    if (!line.trim()) {
      out.push('');
      continue;
    }
    // Numbered ranking lines ("1. Development — ...") already match the
    // existing numbered-list rule; everything else becomes a bullet row so
    // each finding/CVE/contact renders as its own line instead of one
    // giant run-on paragraph.
    if (/^\d+\.\s/.test(line.trim())) {
      out.push(line.trim());
    } else {
      out.push(`- ${line.trim()}`);
    }
  }
  // Collapse the blank-line markers into real paragraph breaks (\n\n) the
  // renderer's `.replace(/\n\n/g, nspacer)` rule expects.
  return out.join('\n').replace(/\n{2,}/g, '\n\n').trim();
}

// ── Display-side dispatcher ─────────────────────────────────────────────
// Markdown-format documents are already exactly what the client's renderer
// wants (real ## headers, real | tables) — reflowing them through the
// delimiter-style bullet logic below would mangle real headers and table
// rows. Only apply that reflow to genuinely old-style documents.
function prepareNarrativeForDisplay(message) {
  if (isMarkdownFormat(message)) return message.trim();
  return narrativeMessageToMarkdown(message);
}

// Derives a clean title for either format — an explicit "# Title" heading
// if present (markdown style), otherwise the message's own first line
// (delimiter style, or a markdown doc with no h1 of its own).
function deriveTitle(message) {
  const h1 = message.match(/^#\s+(.+)$/m);
  if (h1) return h1[1].replace(/[*_`]/g, '').trim();
  const firstLine = message.split('\n')[0].trim();
  return firstLine.replace(/[*_`#]/g, '').trim() || 'Attack Path Analysis';
}

// ── CMDB-driven attack-graph docs (graph.type nested, self-describing edges) ──
// A genuine third document shape — produced by the actual attack-path-writer
// workflow's own ai.prompt step, using real MITRE tactic names rather than
// this project's 4-bucket edge_type vocabulary, and nesting `type` under
// `graph.type` rather than at the document root (so the original top-level
// {type:'node'}/{type:'edge'} query finds nothing for this shape at all).
// Edges are fully self-describing — each embeds complete source/target
// objects — so nodes can be derived straight from edges with no separate
// node documents required.
function mapCriticality(c) {
  const s = (c || '').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(s) ? s : 'medium';
}
function mapCmdbNodeType(t) {
  const s = (t || '').toLowerCase();
  if (s.includes('domain controller')) return 'domain_controller';
  if (s.includes('workstation') || s.includes('laptop')) return 'workstation';
  return 'server';
}
function mapMitreTacticToEdgeType(tactic) {
  const t = (tactic || '').toLowerCase();
  if (t.includes('credential')) return 'credential_access';
  if (t.includes('lateral')) return 'lateral_movement';
  if (t.includes('exfil')) return 'exfiltration';
  return 'data_access'; // Initial Access, Execution, Persistence, Discovery, etc. — no closer bucket
}
function parseCmdbGraphDocs(sources) {
  const nodes = new Map();
  const edges = [];
  const addNode = (obj) => {
    if (!obj?.hostname) return;
    if (!nodes.has(obj.hostname)) {
      nodes.set(obj.hostname, {
        type: 'node', node_id: obj.hostname, label: obj.hostname,
        node_type: mapCmdbNodeType(obj.type), criticality: mapCriticality(obj.criticality),
      });
    }
  };
  sources.forEach(doc => {
    const g = doc.graph;
    if (!g) return;
    if (g.type === 'node' && g.source) { addNode(g.source); return; } // standalone node doc, if ever present
    if (g.type === 'edge' && g.source && g.target) {
      addNode(g.source);
      addNode(g.target);
      edges.push({
        type: 'edge', source_id: g.source.hostname, target_id: g.target.hostname,
        edge_type: mapMitreTacticToEdgeType(g.attack_vector?.tactic),
        description: g.description, technique: g.attack_vector?.technique,
      });
    }
  });
  return { nodes: [...nodes.values()], edges };
}

// ─── Cloudflare Worker entry point ──────────────────────────────────────
// Proxies the two calls the static page needs (list of graph
// nodes/edges, latest narrative) so the real Elasticsearch API key lives
// only in this Worker's encrypted secrets (env.ES_API_KEY) — never in the
// git repo, never in the page source the browser downloads.
//
// Setup:
//   wrangler secret put ES_API_KEY
//   wrangler secret put ES_URL       (e.g. https://<project>.es.<region>.gcp.elastic.cloud)
//   wrangler deploy
// Then point WORKER_URL in index.html at the deployed Worker's URL.

const ALLOWED_ORIGIN = 'https://oneeye-cat.github.io';

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

async function esSearch(env, query, size = 500, sort = null) {
  const body = { size, query };
  if (sort) body.sort = sort;
  const r = await fetch(`${env.ES_URL}/northfield-attack-graph/_search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `ApiKey ${env.ES_API_KEY}` },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()).hits.hits.map(h => h._source);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (!env.ES_URL || !env.ES_API_KEY) {
      return json({ error: 'Worker not configured — set ES_URL and ES_API_KEY secrets.' }, 500);
    }

    try {
      if (url.pathname === '/attack-graph') {
        // Same three-source merge as northfield-forge's server.js: curated
        // baseline, the real CMDB-driven graph.type-nested docs, and the
        // agent's latest free-text narrative — earlier sources win on overlap.
        //
        // match_all previously had no sort and a 500-doc cap — once the
        // index grows past 500 (each CMDB-graph write can add 100+ docs on
        // its own), Elasticsearch's default unsorted order gives no
        // guarantee new documents are among the ones returned, so a fresh
        // write could silently sit outside this window and never even be
        // considered. Sorting by @timestamp desc (missing values pushed
        // last) plus a much higher cap ensures the newest real writes are
        // always included.
        const recencySort = [{ '@timestamp': { order: 'desc', unmapped_type: 'date', missing: '_last' } }];
        const [curatedNodes, curatedEdges, allDocs] = await Promise.all([
          esSearch(env, { term: { type: 'node' } }),
          esSearch(env, { term: { type: 'edge' } }),
          esSearch(env, { match_all: {} }, 5000, recencySort),
        ]);

        const nodeMap = new Map(curatedNodes.map(n => [n.node_id, n]));
        const edgeKey = e => `${e.source_id}->${e.target_id}`;
        const edgeMap = new Map(curatedEdges.map(e => [edgeKey(e), e]));

        const cmdbDocs = allDocs.filter(d => d.graph);
        if (cmdbDocs.length) {
          const parsed = parseCmdbGraphDocs(cmdbDocs);
          parsed.nodes.forEach(n => { if (!nodeMap.has(n.node_id)) nodeMap.set(n.node_id, n); });
          parsed.edges.forEach(e => { if (!edgeMap.has(edgeKey(e))) edgeMap.set(edgeKey(e), e); });
        }

        const narrativeDoc = allDocs
          .filter(d => d.message)
          .sort((a, b) => new Date(b['@timestamp']) - new Date(a['@timestamp']))[0];
        if (narrativeDoc) {
          // Mark every node/edge belonging to the CURRENT narrative's story
          // with highlighted:true — whether it's newly introduced or already
          // existed from curated/CMDB data. This is what lets the client
          // spotlight "the path this specific analysis is about" instead of
          // treating the whole accumulated graph as one undifferentiated pile.
          const parsed = parseNarrativeToGraph(narrativeDoc.message);
          parsed.nodes.forEach(n => {
            if (nodeMap.has(n.node_id)) nodeMap.get(n.node_id).highlighted = true;
            else nodeMap.set(n.node_id, { ...n, highlighted: true });
          });
          parsed.edges.forEach(e => {
            const k = edgeKey(e);
            if (edgeMap.has(k)) edgeMap.get(k).highlighted = true;
            else edgeMap.set(k, { ...e, highlighted: true });
          });
        }

        return json({ nodes: [...nodeMap.values()], edges: [...edgeMap.values()] });
      }

      if (url.pathname === '/attack-graph/metadata') {
        const hits = await esSearch(env, { exists: { field: 'message' } }, 5);
        const doc = hits.sort((a, b) => new Date(b['@timestamp']) - new Date(a['@timestamp']))[0];
        if (!doc) return json({ meta: null });
        return json({
          meta: {
            title: deriveTitle(doc.message),
            narrative: prepareNarrativeForDisplay(doc.message),
            question: null,
            updated_at: doc['@timestamp'],
          },
        });
      }

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: e.message }, 502);
    }
  },
};
