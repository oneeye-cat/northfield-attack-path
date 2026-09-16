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

// Converts the markdown-ish narrative text into an HTML string the client
// can drop straight into innerHTML — headers, bold/code inline formatting,
// tables, and bullet/numbered lines. Done server-side (plain string/regex
// work, no DOM needed) since a Worker has no DOM to build this with anyway,
// and it keeps the client dumb (just inserts the string).
function inlineFormat(s) {
  return s
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}
function renderNarrativeHtml(markdown) {
  const lines = markdown.split('\n');
  const out = [];
  let tableBuf = [];
  const flushTable = () => {
    if (!tableBuf.length) return;
    const rows = tableBuf.filter(r => !/^\|[\s\-:|]+\|$/.test(r.trim()));
    out.push('<table class="ntable">' + rows.map(r => {
      const cells = r.trim().slice(1, -1).split('|').map(c => `<td>${inlineFormat(c.trim())}</td>`);
      return `<tr>${cells.join('')}</tr>`;
    }).join('') + '</table>');
    tableBuf = [];
  };
  lines.forEach(raw => {
    const line = raw.trimEnd();
    const isTableRow = /^\|.*\|$/.test(line.trim());
    if (isTableRow) { tableBuf.push(line); return; }
    flushTable();
    if (/^#\s+/.test(line)) return; // h1 already shown as the page title
    if (/^##\s+/.test(line)) { out.push(`<div class="nh2">${inlineFormat(line.replace(/^##\s+/, ''))}</div>`); return; }
    if (/^###\s+/.test(line)) { out.push(`<div class="nh3">${inlineFormat(line.replace(/^###\s+/, ''))}</div>`); return; }
    if (/^---+$/.test(line.trim())) { out.push('<hr class="ndivider">'); return; }
    if (/^[-*]\s+/.test(line.trim())) { out.push(`<div class="nli">${inlineFormat(line.trim().replace(/^[-*]\s+/, ''))}</div>`); return; }
    if (/^\d+\.\s+/.test(line.trim())) { out.push(`<div class="nli numbered">${inlineFormat(line.trim())}</div>`); return; }
    if (/^>\s*/.test(line.trim())) { out.push(`<div class="nli">${inlineFormat(line.trim().replace(/^>\s*/, ''))}</div>`); return; }
    if (!line.trim()) { out.push('<div class="nspacer"></div>'); return; }
    out.push(`<div class="nli">${inlineFormat(line.trim())}</div>`);
  });
  flushTable();
  return out.join('');
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
  if (s === 'user') return 'user';
  if (s.includes('workstation') || s.includes('laptop') || s.includes('desktop')) return 'workstation';
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

// ── Structured per-run attack-path summary doc ──────────────────────────
// A fourth real document shape: {document_type:'attack_path_summary', ...}
// with an explicit ORDERED attack_phases array, a named most_at_risk_user,
// and structured blast_radius host lists. Far more reliable than parsing
// free prose — when one exists, it's the authoritative signal for "this
// run's story."
//
// Returns { chainSteps, blastRadiusIds, nodesById, edgeType } rather than a
// flat merged graph — the caller needs the chain's actual ORDER (to find
// where a domain-controller/critical-SQL "game over" node first appears
// and truncate everything after it) and the blast-radius set kept SEPARATE
// (dropped entirely once game-over is reached, per how an analyst actually
// reads this: past a DC or critical DB, enumerating what's technically
// reachable next stops being the useful fact — the useful fact is that
// it's over).
function parseMetaSummaryToGraph(doc) {
  const nodesById = new Map();
  const knownUsers = new Set();
  if (doc.most_at_risk_user?.username) knownUsers.add(doc.most_at_risk_user.username);
  if (doc.co_priority_user?.username) knownUsers.add(doc.co_priority_user.username);
  (doc.escalation_contacts || []).forEach(c => { if (c.username) knownUsers.add(c.username); });

  const addNode = (id) => {
    if (nodesById.has(id)) return;
    nodesById.set(id, {
      type: 'node', node_id: id, label: id,
      node_type: knownUsers.has(id) ? 'user' : classifyNodeType(id),
      criticality: knownUsers.has(id) ? 'high' : inferCriticality(id, JSON.stringify(doc)),
    });
  };
  const extractIdentifiers = (text) => {
    const expanded = expandShorthandHostnames(text);
    const hosts = expanded.match(HOSTNAME_RE) || [];
    const users = [...knownUsers].filter(u => text.includes(u));
    return [...new Set([...hosts, ...users])];
  };

  const phases = doc.attack_phases || [];
  let chainSteps = phases.map(extractIdentifiers).filter(g => g.length);
  chainSteps.forEach(group => group.forEach(addNode));

  const edgeType = classifyEdgeType(doc.title || '', phases.join(' '));

  const br = doc.blast_radius || {};
  const blastRadiusIds = [...(br.finance_servers || []), ...(br.it_servers || []), ...(br.domain_controllers || [])];
  blastRadiusIds.forEach(addNode);

  return { chainSteps, blastRadiusIds, nodesById, edgeType };
}

// A domain controller, or a server explicitly named as a critical SQL/DB
// asset, is treated as "game over" — past this point the specific list of
// what else is technically reachable stops being the useful fact.
function isGameOverNode(node) {
  if (!node) return false;
  if (node.node_type === 'domain_controller') return true;
  // Hostname naming convention (NFLD-DC01, NFLD-DC02) as an independent
  // check — the AI-supplied `type` field for these hosts has been observed
  // to say plain "Server" rather than "Domain Controller", so relying on
  // node_type alone misses them.
  if (/^NFLD-DC\d+/i.test(node.node_id)) return true;
  if (node.criticality === 'critical' && /SQL|DB/i.test(node.node_id)) return true;
  return false;
}

// Enriches a set of hostnames/identities with real data from the CMDB
// (owner, department, monitoring status) and Qualys (IP, top CVEs) —
// confirmed field shapes, not guessed. Identity nodes (usernames) are left
// alone: they don't exist in either index, and whatever role/context the
// summary doc itself already gave them is all we have for those.
async function enrichNodes(env, ids) {
  const hostIds = [...new Set(ids)].filter(id => /^NFLD-/.test(id));
  if (!hostIds.length) return {};
  // "terms" queries need an exact-match keyword field — asset.hostname /
  // host.name are very likely mapped as analyzed text with an automatic
  // .keyword sub-field (Elasticsearch's default for string values), so the
  // bare field name silently matches nothing rather than erroring. Errors
  // are surfaced via _meta instead of swallowed, so an empty enrichment
  // result is distinguishable from "this genuinely has no data." _meta is
  // kept OUT of the per-hostname object below — it's added only at the very
  // end, after the per-hostname loop that touches every value in this
  // object has already finished, so it can never be mistaken for a host.
  const errors = [];
  const [cmdbHits, qualysHits] = await Promise.all([
    esSearchIndex(env, 'northfield-cmdb', { terms: { 'asset.hostname.keyword': hostIds } }, hostIds.length)
      .catch(e => { errors.push(`cmdb: ${e.message}`); return []; }),
    esSearchIndex(env, 'northfield-qualys-vulnerabilities', { terms: { 'host.name.keyword': hostIds } }, 2000)
      .catch(e => { errors.push(`qualys: ${e.message}`); return []; }),
  ]);
  const enrichment = {};
  cmdbHits.forEach(d => {
    const h = d.asset?.hostname;
    if (!h) return;
    enrichment[h] = enrichment[h] || {};
    enrichment[h].owner = d.northfield?.cmdb?.owner_username;
    enrichment[h].department = d.organization?.department;
    enrichment[h].monitoring_status = d.northfield?.cmdb?.monitoring_status;
  });
  qualysHits.forEach(d => {
    const h = d.host?.name;
    if (!h) return;
    enrichment[h] = enrichment[h] || {};
    if (!enrichment[h].ip && d.host?.ip?.length) enrichment[h].ip = d.host.ip[0];
    enrichment[h].cves = enrichment[h].cves || [];
    enrichment[h].cves.push({
      id: d.vulnerability?.id,
      cvss: d.vulnerability?.cvss?.v3_1?.base_score ?? d.vulnerability?.score?.base ?? null,
      severity: d.vulnerability?.severity,
      patch_available: d.qualys?.vulnerability?.patch_available,
      times_found: d.qualys?.vulnerability?.times_found,
    });
  });
  Object.values(enrichment).forEach(e => {
    if (e.cves) {
      e.cves.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
      e.cves = e.cves.slice(0, 3); // top 3 by CVSS — a node card isn't a vulnerability report
    }
  });
  enrichment._meta = { errors: errors.length ? errors : null, matched: { cmdb: cmdbHits.length, qualys: qualysHits.length } };
  return enrichment;
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
    // no-store — a GET being cached (by the browser or Cloudflare's edge)
    // was the likely cause of a stale error persisting after a fix had
    // already been deployed; this response should always be fetched fresh.
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders() },
  });
}

async function esSearch(env, query, size = 500, sort = null) {
  return esSearchIndex(env, 'northfield-attack-graph', query, size, sort);
}
async function esSearchIndex(env, index, query, size = 500, sort = null) {
  const data = await esRawSearch(env, index, { size, query, ...(sort ? { sort } : {}) });
  return data.hits.hits.map(h => h._source);
}
async function esRawSearch(env, index, body) {
  const r = await fetch(`${env.ES_URL}/${index}/_search`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `ApiKey ${env.ES_API_KEY}` },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// 14-day rolling alert count per host, via a terms aggregation rather than
// fetching hits — this index has at least 10,000 documents, so counting via
// aggregation (not size:0-and-still-scanning-hits) is the only sane way to
// do this cheaply.
async function fetchAlertCounts(env, hostIds, days = 14) {
  if (!hostIds.length) return {};
  const body = {
    size: 0,
    query: { bool: { filter: [
      { terms: { 'host.name.keyword': hostIds } },
      { range: { '@timestamp': { gte: `now-${days}d` } } },
    ] } },
    aggs: { by_host: { terms: { field: 'host.name.keyword', size: 1000 } } },
  };
  const data = await esRawSearch(env, '.alerts-security.alerts-default', body);
  const counts = {};
  (data.aggregations?.by_host?.buckets || []).forEach(b => { counts[b.key] = b.doc_count; });
  return counts;
}

// The actual alert list for one host, for the click-to-expand popout.
// kibana.alert.url is a direct link into the real Kibana Security alert
// view — surfaced as-is so the popout is a genuine jump-off point into the
// real investigation UI, not just a read-only summary.
async function fetchAlertList(env, host, days = 14, size = 50) {
  const body = {
    size,
    sort: [{ '@timestamp': { order: 'desc' } }],
    query: { bool: { filter: [
      { term: { 'host.name.keyword': host } },
      { range: { '@timestamp': { gte: `now-${days}d` } } },
    ] } },
  };
  const data = await esRawSearch(env, '.alerts-security.alerts-default', body);
  return (data.hits?.hits || []).map(h => ({
    rule: h._source['kibana.alert.rule.name'],
    severity: h._source['kibana.alert.severity'],
    riskScore: h._source['kibana.alert.risk_score'],
    reason: h._source['kibana.alert.reason'],
    timestamp: h._source['@timestamp'],
    url: h._source['kibana.alert.url'],
  }));
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
        // No merged/background view — the page shows ONLY the latest run's
        // story. "Latest" is decided by Elasticsearch's own server-assigned
        // _seq_no (monotonic, reliable on this single-shard index) — NOT
        // by the AI-supplied @timestamp field, which has been observed to
        // sometimes be midnight-normalized (date-only, no real time) rather
        // than a genuine timestamp. Relying on @timestamp for cross-type
        // "which run is newest" comparison meant a stale summary doc with a
        // real time-of-day could outrank a genuinely fresher run that
        // happened to get a midnight-normalized one — exactly the bug that
        // made a new run's data never appear. _seq_no order fixes that
        // regardless of what the AI puts in @timestamp.
        const seqNoSort = [{ '_seq_no': { order: 'desc' } }];
        const allDocs = await esSearch(env, { match_all: {} }, 5000, seqNoSort);

        let winnerType = null, winnerDoc = null;
        for (const d of allDocs) {
          if (d.document_type === 'attack_path_summary') { winnerType = 'summary'; winnerDoc = d; break; }
          if (d.message) { winnerType = 'narrative'; winnerDoc = d; break; }
          if (d.graph) { winnerType = 'cmdb'; winnerDoc = d; break; }
        }
        const summaryDoc = winnerType === 'summary' ? winnerDoc : null;
        const narrativeForChainDoc = winnerType === 'narrative' ? winnerDoc : null;
        // The full-text "attack story" section is independent of which type
        // won the chain — still whichever message-doc is most recent overall.
        const narrativeDoc = allDocs.filter(d => d.message)[0];

        let title = null, narrative = null, updatedAt = null;
        let chainSteps = [], blastRadiusIds = [], nodesById = new Map(), edgeType = 'data_access';

        if (summaryDoc) {
          const parsed = parseMetaSummaryToGraph(summaryDoc);
          chainSteps = parsed.chainSteps;
          blastRadiusIds = parsed.blastRadiusIds;
          nodesById = parsed.nodesById;
          edgeType = parsed.edgeType;
          title = summaryDoc.title || null;
          narrative = summaryDoc.description || null;
          updatedAt = summaryDoc['@timestamp'];
        } else if (narrativeForChainDoc) {
          const parsed = parseNarrativeToGraph(narrativeForChainDoc.message);
          // parseNarrativeToGraph returns a flat graph, not phase-ordered
          // steps — approximate a chain from node insertion order (still
          // reasonable, since that parser also builds nodes in the order
          // they're encountered in the text).
          chainSteps = parsed.nodes.map(n => [n.node_id]);
          parsed.nodes.forEach(n => nodesById.set(n.node_id, n));
          title = deriveTitle(narrativeForChainDoc.message);
          narrative = null;
          updatedAt = narrativeForChainDoc['@timestamp'];
        } else if (winnerType === 'cmdb') {
          // Group the whole run's batch by matching @timestamp — still
          // valid WITHIN one run (a single execution writes all its docs
          // with the same value, whatever its granularity), just not
          // reliable for comparing ACROSS different runs, which is why
          // _seq_no (not this) decided which run won above.
          const latestTs = winnerDoc['@timestamp'];
          const latestBatch = allDocs.filter(d => d.graph && d['@timestamp'] === latestTs);
          const parsed = parseCmdbGraphDocs(latestBatch);
          chainSteps = parsed.nodes.map(n => [n.node_id]);
          parsed.nodes.forEach(n => nodesById.set(n.node_id, n));
          updatedAt = latestTs || null;
        } else {
          return json({ title: null, narrative: null, chain: [], blastRadius: [], gameOver: false, updated_at: null });
        }

        // "Game over" — once the chain reaches a domain controller or a
        // critical SQL/DB server, stop enumerating what's technically
        // reachable next. Truncate the chain right there and drop the
        // blast-radius list entirely.
        let gameOverAt = -1;
        for (let i = 0; i < chainSteps.length; i++) {
          if (chainSteps[i].some(id => isGameOverNode(nodesById.get(id)))) { gameOverAt = i; break; }
        }
        const gameOver = gameOverAt !== -1;
        const effectiveChainSteps = gameOver ? chainSteps.slice(0, gameOverAt + 1) : chainSteps;
        const effectiveBlastRadius = gameOver ? [] : blastRadiusIds;

        // Enrich every real host in the final chain + blast radius with
        // live CMDB (owner/department/monitoring) and Qualys (IP/top CVEs)
        // data — confirmed field shapes, not guessed.
        const allIds = [...new Set([...effectiveChainSteps.flat(), ...effectiveBlastRadius])];
        const [enrichment, alertCounts] = await Promise.all([
          enrichNodes(env, allIds).catch(() => ({})),
          fetchAlertCounts(env, allIds).catch(() => ({})),
        ]);

        // The full agent narrative — independent of which doc drove the
        // chain above, EXCEPT it must not be older than whatever drove the
        // chain (by _seq_no position in the already-sorted allDocs), or a
        // stale narrative from a previous run would show alongside a fresh
        // chain from a run that didn't happen to write one — exactly the
        // kind of mismatch a genuinely new run with no message doc would
        // otherwise cause.
        let storyHtml = null;
        if (narrativeDoc && winnerDoc && allDocs.indexOf(narrativeDoc) <= allDocs.indexOf(winnerDoc)) {
          storyHtml = renderNarrativeHtml(prepareNarrativeForDisplay(narrativeDoc.message));
        }

        const enrich = id => {
          const node = nodesById.get(id) || { node_id: id, label: id, node_type: classifyNodeType(id), criticality: 'medium' };
          return { ...node, ...(enrichment[id] || {}), alertCount14d: alertCounts[id] || 0 };
        };

        const chain = effectiveChainSteps.map(step => step.map(enrich));
        const blastRadius = effectiveBlastRadius.map(enrich);

        return json({
          title, narrative,
          chain, blastRadius, gameOver,
          edgeType,
          storyHtml,
          updated_at: updatedAt,
          debug: enrichment._meta,
        });
      }

      if (url.pathname === '/alerts') {
        const host = url.searchParams.get('host');
        if (!host) return json({ error: 'Missing ?host= parameter' }, 400);
        const days = parseInt(url.searchParams.get('days') || '14', 10);
        const alerts = await fetchAlertList(env, host, days);
        return json({ host, days, alerts });
      }

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      // Include the stack's top frame so a future error says WHICH line
      // failed, rather than needing another round of blind guessing.
      const topFrame = (e.stack || '').split('\n')[1]?.trim() || '';
      return json({ error: e.message, at: topFrame }, 502);
    }
  },
};
