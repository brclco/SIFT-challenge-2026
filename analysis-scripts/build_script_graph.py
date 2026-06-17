#!/usr/bin/env python3
"""build_script_graph.py — generate an interactive HTML map of the repo's scripts.

Walks the repository for every .py / .sh script, draws a force-directed graph of how they
relate (imports / launches / validates-via / vets / registers), and embeds each script's
source so clicking a node opens it in a sidebar. Scripts with no relationships are included
as solitary (floating) nodes.

Relationships are declared explicitly in EDGES below (derived from the actual imports and
cross-references in the code); re-run this after structural changes.

Usage:  python3 analysis-scripts/build_script_graph.py [REPO_ROOT] [OUT_HTML]
Default: REPO_ROOT = repo root (parent of this script's dir), OUT = docs/script_graph.html
"""

import html
import os
import sys

# (source, target, label) — repo-relative paths.
EDGES = [
    # sift-mcp-server: server imports each tool + the audit parser
    ("sift-mcp-server/server.py", "sift-mcp-server/parsers/audit.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/volatility.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/evtx.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/lotl.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/filesystem.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/carve.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/registry.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/network.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/yara.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/timeline.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/amcache.py", "imports"),
    ("sift-mcp-server/server.py", "sift-mcp-server/tools/casedata.py", "imports"),
    # each tool imports the shared parser helpers
    ("sift-mcp-server/tools/filesystem.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/volatility.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/timeline.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/evtx.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/carve.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/registry.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/amcache.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/lotl.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/yara.py", "sift-mcp-server/parsers/common.py", "imports"),
    ("sift-mcp-server/tools/network.py", "sift-mcp-server/parsers/common.py", "imports"),
    # cross-language wiring
    ("agent/guardrails.py", "gateway/runclawd_exec_gateway.py", "calls (HTTP :12345)"),
    ("hooks/pre_tool_use.sh", "gateway/runclawd_exec_gateway.py", "validates via"),
    ("hooks/ensure_gateway.sh", "gateway/runclawd_exec_gateway.py", "launches"),
    ("web/dashboard.py", "gateway/runclawd_exec_gateway.py", "reads audit / mode"),
    ("web/dashboard.py", "agent/guardrails.py", "mode toggle"),
    ("gateway/runclawd_exec_gateway.py", "agent/guardrails.py", "vets (allowlist)"),
    ("install.sh", "gateway/runclawd_exec_gateway.py", "launches"),
    ("install.sh", "sift-mcp-server/server.py", "registers (MCP)"),
    ("install.sh", "web/dashboard.py", "documents"),
    ("install.sh", "analysis-scripts/generate_report.py", "documents"),
]

# top-level dir -> (group key, colour)
GROUPS = {
    "sift-mcp-server": ("mcp", "#3fb950"),
    "gateway": ("gateway", "#f85149"),
    "agent": ("agent", "#d29922"),
    "hooks": ("hooks", "#a371f7"),
    "web": ("web", "#58a6ff"),
    "analysis-scripts": ("analysis", "#39c5cf"),
    "(root)": ("root", "#f0883e"),
}


def group_of(relpath):
    top = relpath.split("/", 1)[0] if "/" in relpath else "(root)"
    return GROUPS.get(top, ("root", "#8b949e"))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.dirname(here)
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(root, "docs", "script_graph.html")

    # discover all scripts
    scripts = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", ".venv")]
        for fn in filenames:
            if fn.endswith((".py", ".sh")):
                rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/")
                scripts.append(rel)
    scripts.sort()

    idx = {rel: i for i, rel in enumerate(scripts)}
    connected = set()
    for s, t, _ in EDGES:
        connected.add(s); connected.add(t)

    # build node + link JSON (hand-rolled to avoid deps)
    nodes_js = []
    textareas = []
    for i, rel in enumerate(scripts):
        gkey, colour = group_of(rel)
        label = rel.split("/")[-1]
        solitary = rel not in connected
        nodes_js.append(
            '{id:%d,path:%s,label:%s,group:%s,color:%s,solitary:%s}'
            % (i, _q(rel), _q(label), _q(gkey), _q(colour), "true" if solitary else "false")
        )
        try:
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError:
            src = "(could not read file)"
        textareas.append(
            '<textarea hidden id="src-%d">%s</textarea>' % (i, html.escape(src))
        )

    links_js = []
    for s, t, lbl in EDGES:
        if s in idx and t in idx:
            links_js.append('{source:%d,target:%d,label:%s}' % (idx[s], idx[t], _q(lbl)))

    n_sol = sum(1 for rel in scripts if rel not in connected)
    html_doc = TEMPLATE.format(
        nodes=",\n".join(nodes_js),
        links=",\n".join(links_js),
        textareas="\n".join(textareas),
        count=len(scripts),
        edges=len(links_js),
        solitary=n_sol,
    )
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html_doc)
    print("[OK] wrote %s  (%d scripts, %d relationships, %d solitary)"
          % (out, len(scripts), len(links_js), n_sol))


def _q(s):
    """JS string literal."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Find Evil! — Script Relationship Map</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html, body {{ width: 100%; height: 100%; background: #0d1117; overflow: hidden;
    font-family: 'Segoe UI', system-ui, sans-serif; color: #e6edf3; }}
  header {{ position: fixed; top: 0; left: 0; right: 0; z-index: 100; height: 42px;
    background: #161b22; border-bottom: 1px solid #30363d; padding: 9px 16px;
    display: flex; align-items: center; gap: 14px; }}
  header h1 {{ font-size: 14px; font-weight: 600; color: #58a6ff; white-space: nowrap; }}
  .hint {{ font-size: 11px; color: #6e7681; }}
  .spacer {{ flex: 1; }}
  .btn {{ background: #21262d; border: 1px solid #30363d; border-radius: 5px;
    padding: 4px 10px; color: #e6edf3; font-size: 11px; cursor: pointer; }}
  .btn:hover {{ background: #30363d; }}
  #chart {{ position: fixed; top: 42px; left: 0; right: 0; bottom: 0; }}
  /* sidebar */
  #side {{ position: fixed; top: 42px; right: 0; bottom: 0; width: 46%; max-width: 760px;
    background: #0b0f14; border-left: 1px solid #30363d; z-index: 90;
    transform: translateX(100%); transition: transform .18s ease; display: flex;
    flex-direction: column; }}
  #side.open {{ transform: translateX(0); box-shadow: -12px 0 30px rgba(0,0,0,.45); }}
  #side-hd {{ display: flex; align-items: center; gap: 10px; padding: 9px 12px;
    border-bottom: 1px solid #30363d; background: #161b22; }}
  #side-hd .path {{ font-family: ui-monospace, monospace; font-size: 12.5px; color: #e6edf3;
    word-break: break-all; }}
  #side-hd .tag {{ font-size: 10px; padding: 2px 7px; border-radius: 10px; color: #0d1117;
    font-weight: 700; white-space: nowrap; }}
  #side pre {{ margin: 0; padding: 12px 14px; overflow: auto; flex: 1;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
    line-height: 1.5; color: #c9d1d9; white-space: pre; tab-size: 4; }}
  #close {{ margin-left: auto; }}
  #tip {{ position: fixed; background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: 5px 9px; font-family: ui-monospace, monospace; font-size: 11.5px; color: #e6edf3;
    pointer-events: none; opacity: 0; transition: opacity .1s; z-index: 200; }}
  .node-label {{ font-family: ui-monospace, monospace; font-size: 10px; fill: #adbac7;
    pointer-events: none; }}
  .edge-label {{ font-size: 8.5px; fill: #6e7681; pointer-events: none; }}
  #legend {{ position: fixed; left: 12px; bottom: 12px; z-index: 80; background: #161b22cc;
    border: 1px solid #30363d; border-radius: 7px; padding: 8px 10px; font-size: 11px; }}
  #legend div {{ display: flex; align-items: center; gap: 7px; margin: 2px 0; }}
  #legend i {{ width: 10px; height: 10px; border-radius: 2px; display: inline-block; }}
</style>
</head>
<body>
<header>
  <h1>Find Evil! — Script Relationship Map</h1>
  <span class="hint">{count} scripts · {edges} relationships · {solitary} solitary — click a node to view its source · scroll to zoom · drag to pan/move</span>
  <div class="spacer"></div>
  <button class="btn" id="btn-reset">Reset view</button>
</header>
<div id="chart"></div>
<div id="tip"></div>
<div id="legend"></div>
<aside id="side">
  <div id="side-hd"><span class="tag" id="side-tag"></span><span class="path" id="side-path"></span>
    <button class="btn" id="close">close ✕</button></div>
  <pre id="side-code"></pre>
</aside>

{textareas}

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
"use strict";
const NODES = [
{nodes}
];
const LINKS = [
{links}
];

const GROUP_COLORS = {{}};
NODES.forEach(n => GROUP_COLORS[n.group] = n.color);

// legend
const legend = document.getElementById("legend");
Object.entries(GROUP_COLORS).forEach(([g,c]) => {{
  const row = document.createElement("div");
  row.innerHTML = '<i style="background:'+c+'"></i><span>'+g+'</span>';
  legend.appendChild(row);
}});

const chart = document.getElementById("chart");
const W = () => chart.clientWidth, H = () => chart.clientHeight;
const svg = d3.select("#chart").append("svg").attr("width","100%").attr("height","100%");
const defs = svg.append("defs");
defs.append("marker").attr("id","arrow").attr("viewBox","0 -5 10 10")
  .attr("refX",22).attr("refY",0).attr("markerWidth",6).attr("markerHeight",6)
  .attr("orient","auto").append("path").attr("d","M0,-5L10,0L0,5").attr("fill","#6e7681");

const g = svg.append("g");
svg.call(d3.zoom().scaleExtent([0.15,4]).on("zoom", e => g.attr("transform", e.transform)))
   .on("dblclick.zoom", null);

const link = g.append("g").selectAll("line").data(LINKS).join("line")
  .attr("stroke","#3d444d").attr("stroke-width",1.4).attr("marker-end","url(#arrow)");
const elabel = g.append("g").selectAll("text").data(LINKS).join("text")
  .attr("class","edge-label").text(d => d.label);

const node = g.append("g").selectAll("g").data(NODES).join("g").style("cursor","pointer");
node.append("circle")
  .attr("r", d => d.solitary ? 7 : 9)
  .attr("fill", d => d.color)
  .attr("stroke", d => d.solitary ? "#6e7681" : "#0d1117")
  .attr("stroke-width", d => d.solitary ? 1.5 : 2)
  .attr("stroke-dasharray", d => d.solitary ? "2,2" : null);
node.append("text").attr("class","node-label").attr("x",12).attr("y",4).text(d => d.label);

const tip = document.getElementById("tip");
node.on("mouseover",(e,d)=>{{tip.textContent=d.path;tip.style.opacity=1;}})
    .on("mousemove",e=>{{tip.style.left=(e.clientX+12)+"px";tip.style.top=(e.clientY+12)+"px";}})
    .on("mouseout",()=>tip.style.opacity=0)
    .on("click",(e,d)=>openSide(d));

const sim = d3.forceSimulation(NODES)
  .force("link", d3.forceLink(LINKS).distance(95).strength(0.6))
  .force("charge", d3.forceManyBody().strength(-380))
  .force("collide", d3.forceCollide(34))
  .force("center", d3.forceCenter(W()/2, H()/2))
  .force("x", d3.forceX(W()/2).strength(0.04))
  .force("y", d3.forceY(H()/2).strength(0.04))
  .on("tick", ticked);

function ticked() {{
  link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  elabel.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2);
  node.attr("transform",d=>`translate(${{d.x}},${{d.y}})`);
}}
node.call(d3.drag()
  .on("start",(e,d)=>{{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;}})
  .on("drag",(e,d)=>{{d.fx=e.x;d.fy=e.y;}})
  .on("end",(e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}}));

// sidebar
const side=document.getElementById("side");
function openSide(d){{
  document.getElementById("side-path").textContent=d.path;
  const tag=document.getElementById("side-tag");
  tag.textContent=d.group; tag.style.background=d.color;
  const ta=document.getElementById("src-"+d.id);
  document.getElementById("side-code").textContent = ta ? ta.value : "(source unavailable)";
  side.classList.add("open");
}}
document.getElementById("close").onclick=()=>side.classList.remove("open");

document.getElementById("btn-reset").onclick=()=>{{
  svg.transition().duration(400).call(
    d3.zoom().transform, d3.zoomIdentity);
  sim.alpha(0.6).restart();
}};
window.addEventListener("resize",()=>{{
  sim.force("center", d3.forceCenter(W()/2,H()/2)); sim.alpha(0.3).restart();
}});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
