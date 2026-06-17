#!/usr/bin/env python3
"""build_script_graph.py — interactive collapsible mind-map of the repo's scripts + configs.

Renders a tree you expand by clicking: it starts at the entry point (install.sh) and reveals
what each node pulls in (imports / launches / validates-via / vets / registers / wires) only
when you click it. Click any real script or JSON to view its source in the sidebar. Cycles are
shown once and then as "↩" references; shared dependencies appear once at first encounter.
Files not wired into the run (the graph generator, package __init__ markers, an unused config)
are grouped under a "Standalone" node so nothing is hidden.

Usage:  python3 analysis-scripts/build_script_graph.py [REPO_ROOT] [OUT_HTML]
Default OUT: docs/script_graph.html
"""

import html
import json
import os
import sys

# parent rel-path -> [(child rel-path, relationship label)]
ADJ = {
    "install.sh": [
        ("gateway/runclawd_exec_gateway.py", "launches"),
        ("sift-mcp-server/server.py", "registers (MCP)"),
        ("web/dashboard.py", "documents"),
        ("analysis-scripts/generate_report.py", "documents"),
        ("agent/settings.json", "wires hooks"),
    ],
    "gateway/runclawd_exec_gateway.py": [
        ("agent/guardrails.py", "vets (allowlist)"),
    ],
    "agent/guardrails.py": [
        ("gateway/runclawd_exec_gateway.py", "calls (HTTP :12345)"),
        ("reference/ttp_reference.json", "judge TTP cross-check"),
    ],
    "sift-mcp-server/server.py": [
        ("sift-mcp-server/parsers/audit.py", "imports"),
        ("sift-mcp-server/tools/volatility.py", "imports"),
        ("sift-mcp-server/tools/evtx.py", "imports"),
        ("sift-mcp-server/tools/lotl.py", "imports"),
        ("sift-mcp-server/tools/filesystem.py", "imports"),
        ("sift-mcp-server/tools/carve.py", "imports"),
        ("sift-mcp-server/tools/registry.py", "imports"),
        ("sift-mcp-server/tools/network.py", "imports"),
        ("sift-mcp-server/tools/yara.py", "imports"),
        ("sift-mcp-server/tools/timeline.py", "imports"),
        ("sift-mcp-server/tools/amcache.py", "imports"),
        ("sift-mcp-server/tools/casedata.py", "imports"),
    ],
    "web/dashboard.py": [
        ("gateway/runclawd_exec_gateway.py", "reads audit / mode"),
        ("agent/guardrails.py", "mode toggle"),
    ],
    "agent/settings.json": [
        ("hooks/pre_tool_use.sh", "PreToolUse hook"),
        ("hooks/ensure_gateway.sh", "SessionStart hook"),
    ],
    "hooks/pre_tool_use.sh": [
        ("gateway/runclawd_exec_gateway.py", "validates via"),
    ],
    "hooks/ensure_gateway.sh": [
        ("gateway/runclawd_exec_gateway.py", "launches"),
    ],
}
for _t in ("volatility", "evtx", "lotl", "filesystem", "carve", "registry",
           "network", "yara", "timeline", "amcache"):
    ADJ["sift-mcp-server/tools/%s.py" % _t] = [
        ("sift-mcp-server/parsers/common.py", "imports")]

ROOT = "install.sh"

GROUPS = {
    "sift-mcp-server": ("mcp", "#3fb950"),
    "gateway": ("gateway", "#f85149"),
    "agent": ("agent", "#d29922"),
    "hooks": ("hooks", "#a371f7"),
    "web": ("web", "#58a6ff"),
    "analysis-scripts": ("analysis", "#39c5cf"),
    "reference": ("reference", "#e3b341"),
    "(root)": ("root", "#f0883e"),
}


def group_of(rel):
    top = rel.split("/", 1)[0] if "/" in rel else "(root)"
    return GROUPS.get(top, ("root", "#8b949e"))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.dirname(here)
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(root_dir, "docs", "script_graph.html")

    files = []
    for dp, dn, fn in os.walk(root_dir):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__", ".venv")]
        for f in fn:
            if f.endswith((".py", ".sh", ".json")):
                files.append(os.path.relpath(os.path.join(dp, f), root_dir).replace(os.sep, "/"))
    files.sort()
    src_index = {rel: i for i, rel in enumerate(files)}

    # reachable from ROOT
    reachable, stack = set(), [ROOT]
    while stack:
        cur = stack.pop()
        if cur in reachable:
            continue
        reachable.add(cur)
        for c, _ in ADJ.get(cur, []):
            stack.append(c)
    standalone = sorted(f for f in files if f not in reachable)

    counter = [0]
    expanded = set()

    def node_for(rel, edge, ancestors):
        nid = counter[0]; counter[0] += 1
        gkey, color = group_of(rel)
        n = {"id": nid, "name": rel.split("/")[-1], "path": rel, "edge": edge,
             "group": gkey, "color": color, "srcId": src_index.get(rel),
             "kind": "json" if rel.endswith(".json") else "script"}
        specs = ADJ.get(rel, [])
        if specs:
            if rel in ancestors or rel in expanded:
                n["kind"] = "ref"; n["name"] += "  ↩"
            else:
                expanded.add(rel)
                n["children"] = [node_for(c, lbl, ancestors + [rel]) for c, lbl in specs]
        return n

    def syn(name, edge, desc, children):
        nid = counter[0]; counter[0] += 1
        return {"id": nid, "name": name, "edge": edge, "desc": desc, "kind": "synthetic",
                "group": "root", "color": "#8b949e", "srcId": None, "children": children}

    tree = syn(
        "Find Evil! scripts", "",
        "The Find Evil! script tree. Click a node to reveal what it pulls in; click again to "
        "collapse. Click any script or JSON to view its source here. '↩' marks a node "
        "shown in full elsewhere (cycle or shared dependency).",
        [
            node_for(ROOT, "entry point", []),
            syn("Standalone (%d)" % len(standalone), "not wired into the run",
                "Files no other script imports, launches, or references at runtime: the graph "
                "generator, Python package __init__ markers, and an unused MCP settings copy.",
                [node_for(p, "standalone", []) for p in standalone]),
        ],
    )

    textareas = []
    for rel, i in src_index.items():
        try:
            with open(os.path.join(root_dir, rel), encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError:
            src = "(could not read file)"
        textareas.append('<textarea hidden id="src-%d">%s</textarea>' % (i, html.escape(src)))

    htmldoc = (TEMPLATE
               .replace("__TREEDATA__", json.dumps(tree))
               .replace("__TEXTAREAS__", "\n".join(textareas))
               .replace("__COUNT__", str(len(files)))
               .replace("__SOLO__", str(len(standalone))))
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(htmldoc)
    print("[OK] wrote %s  (%d files, %d standalone)" % (out, len(files), len(standalone)))


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Find Evil! — Script Mind-Map</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { width:100%; height:100%; background:#0d1117; overflow:hidden;
    font-family:'Segoe UI',system-ui,sans-serif; color:#e6edf3; }
  header { position:fixed; top:0; left:0; right:0; z-index:100; height:42px; background:#161b22;
    border-bottom:1px solid #30363d; padding:9px 16px; display:flex; align-items:center; gap:14px; }
  header h1 { font-size:14px; font-weight:600; color:#58a6ff; white-space:nowrap; }
  .hint { font-size:11px; color:#6e7681; }
  .spacer { flex:1; }
  .btn { background:#21262d; border:1px solid #30363d; border-radius:5px; padding:4px 10px;
    color:#e6edf3; font-size:11px; cursor:pointer; }
  .btn:hover { background:#30363d; }
  #chart { position:fixed; top:42px; left:0; right:0; bottom:0; }
  #side { position:fixed; top:42px; right:0; bottom:0; width:46%; max-width:760px; background:#0b0f14;
    border-left:1px solid #30363d; z-index:90; transform:translateX(100%); transition:transform .18s ease;
    display:flex; flex-direction:column; }
  #side.open { transform:translateX(0); box-shadow:-12px 0 30px rgba(0,0,0,.45); }
  #side-hd { display:flex; align-items:center; gap:10px; padding:9px 12px; border-bottom:1px solid #30363d;
    background:#161b22; }
  #side-hd .path { font-family:ui-monospace,monospace; font-size:12.5px; word-break:break-all; }
  #side-hd .tag { font-size:10px; padding:2px 7px; border-radius:10px; color:#0d1117; font-weight:700;
    white-space:nowrap; }
  #side pre { margin:0; padding:12px 14px; overflow:auto; flex:1;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; line-height:1.5;
    color:#c9d1d9; white-space:pre; tab-size:4; }
  #close { margin-left:auto; }
  #tip { position:fixed; background:#161b22; border:1px solid #30363d; border-radius:6px; padding:5px 9px;
    font-family:ui-monospace,monospace; font-size:11.5px; pointer-events:none; opacity:0;
    transition:opacity .1s; z-index:200; max-width:340px; }
  .link { fill:none; stroke:#3d444d; stroke-width:1.5px; }
  .nlabel { font-family:ui-monospace,monospace; font-size:11px; fill:#adbac7; }
  .elabel { font-size:9px; fill:#6e7681; }
  .ref text { font-style:italic; }
  #legend { position:fixed; left:12px; bottom:12px; z-index:80; background:#161b22cc;
    border:1px solid #30363d; border-radius:7px; padding:8px 10px; font-size:11px; }
  #legend div { display:flex; align-items:center; gap:7px; margin:2px 0; }
  #legend i { width:10px; height:10px; border-radius:2px; display:inline-block; }
</style>
</head>
<body>
<header>
  <h1>Find Evil! — Script Mind-Map</h1>
  <span class="hint">__COUNT__ scripts/configs · __SOLO__ standalone — click a node to expand · click a file to view its source · scroll/drag to zoom &amp; pan</span>
  <div class="spacer"></div>
  <button class="btn" id="btn-expand">Expand all</button>
  <button class="btn" id="btn-reset">Collapse / reset</button>
</header>
<div id="chart"></div>
<div id="tip"></div>
<div id="legend"></div>
<aside id="side">
  <div id="side-hd"><span class="tag" id="side-tag"></span><span class="path" id="side-path"></span>
    <button class="btn" id="close">close ✕</button></div>
  <pre id="side-code"></pre>
</aside>

__TEXTAREAS__

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<script>
"use strict";
const DATA = __TREEDATA__;

const COLORS = {};
(function walk(n){ if(n.color) COLORS[n.group]=n.color; (n.children||[]).forEach(walk); })(DATA);
const legend = document.getElementById("legend");
Object.entries(COLORS).forEach(([g,c])=>{ const d=document.createElement("div");
  d.innerHTML='<i style="background:'+c+'"></i><span>'+g+'</span>'; legend.appendChild(d); });

const chart=document.getElementById("chart");
const svg=d3.select("#chart").append("svg").attr("width","100%").attr("height","100%");
const defs=svg.append("defs");
defs.append("marker").attr("id","arr").attr("viewBox","0 -5 10 10").attr("refX",16).attr("refY",0)
  .attr("markerWidth",5).attr("markerHeight",5).attr("orient","auto")
  .append("path").attr("d","M0,-5L10,0L0,5").attr("fill","#6e7681");
const g=svg.append("g");
const zoom=d3.zoom().scaleExtent([0.2,3]).on("zoom",e=>g.attr("transform",e.transform));
svg.call(zoom).on("dblclick.zoom",null);

const DX=26, DY=270;     // row height, column width
const tree=d3.tree().nodeSize([DX,DY]);
const root=d3.hierarchy(DATA);
root.x0=0; root.y0=0;
let uid=0; root.descendants().forEach(d=>{ d._id = ++uid; });

// start collapsed: root + its direct children visible, everything deeper hidden
function collapse(d){ if(d.children){ d._children=d.children; d._children.forEach(collapse); d.children=null; } }
(root.children||[]).forEach(collapse);
update(root);
setTimeout(fit, 60);

function update(source){
  tree(root);
  const nodes=root.descendants(), links=root.links();
  let minx=Infinity,maxx=-Infinity;
  nodes.forEach(d=>{ minx=Math.min(minx,d.x); maxx=Math.max(maxx,d.x); });

  const node=g.selectAll("g.node").data(nodes, d=>d._id);
  const nEnter=node.enter().append("g").attr("class",d=>"node"+(d.data.kind==="ref"?" ref":""))
    .attr("transform",d=>`translate(${source.y0},${source.x0})`)
    .style("cursor","pointer").on("click",(e,d)=>{ toggle(d); openSide(d); })
    .on("mouseover",(e,d)=>{ tip.textContent=(d.data.path||d.data.name)+(d.data.edge?"  —  "+d.data.edge:""); tip.style.opacity=1; })
    .on("mousemove",e=>{ tip.style.left=(e.clientX+12)+"px"; tip.style.top=(e.clientY+12)+"px"; })
    .on("mouseout",()=>tip.style.opacity=0);
  nEnter.append("circle").attr("r",5.5)
    .attr("fill",d=> (d._children) ? d.data.color : (d.data.kind==="synthetic" ? "#0d1117" : d.data.color))
    .attr("stroke",d=>d.data.color).attr("stroke-width",2)
    .attr("stroke-dasharray",d=>d.data.kind==="ref"?"2,2":null);
  nEnter.append("text").attr("class","nlabel").attr("dy",4)
    .attr("x",d=>d.children||d._children?-10:10).attr("text-anchor",d=>d.children||d._children?"end":"start")
    .text(d=>d.data.name + ((d._children&&d._children.length)?"  ▸":""));
  const tip=document.getElementById("tip");

  const nUpd=nEnter.merge(node);
  nUpd.transition().duration(180).attr("transform",d=>`translate(${d.y},${d.x})`);
  nUpd.select("text").text(d=>d.data.name + ((d._children&&d._children.length)?"  ▸":""))
    .attr("x",d=>d.children||d._children?-10:10).attr("text-anchor",d=>d.children||d._children?"end":"start");
  nUpd.select("circle").attr("fill",d=>(d._children)?d.data.color:(d.data.kind==="synthetic"?"#0d1117":d.data.color));
  node.exit().transition().duration(180).attr("transform",d=>`translate(${source.y},${source.x})`).remove();

  const link=g.selectAll("path.link").data(links, d=>d.target._id);
  const lEnter=link.enter().insert("path","g").attr("class","link").attr("marker-end","url(#arr)")
    .attr("d",()=>{ const o={x:source.x0,y:source.y0}; return diag(o,o); });
  lEnter.merge(link).transition().duration(180).attr("d",d=>diag(d.source,d.target));
  link.exit().transition().duration(180).attr("d",()=>{ const o={x:source.x,y:source.y}; return diag(o,o); }).remove();

  const el=g.selectAll("text.elabel").data(links, d=>d.target._id);
  const elEnter=el.enter().append("text").attr("class","elabel").attr("dy",-3).text(d=>d.target.data.edge||"");
  elEnter.merge(el).transition().duration(180)
    .attr("x",d=>(d.source.y+d.target.y)/2).attr("y",d=>(d.source.x+d.target.x)/2).attr("text-anchor","middle");
  el.exit().remove();

  nodes.forEach(d=>{ d.x0=d.x; d.y0=d.y; });
}
function diag(s,t){ return `M${s.y},${s.x}C${(s.y+t.y)/2},${s.x} ${(s.y+t.y)/2},${t.x} ${t.y},${t.x}`; }
function toggle(d){ if(d.children){ d._children=d.children; d.children=null; } else if(d._children){ d.children=d._children; d._children=null; } update(d); }

function expandAll(d){ if(d._children){ d.children=d._children; d._children=null; } (d.children||[]).forEach(expandAll); }

const side=document.getElementById("side");
function openSide(d){
  document.getElementById("side-path").textContent = d.data.path || d.data.name;
  const tag=document.getElementById("side-tag"); tag.textContent=d.data.group; tag.style.background=d.data.color;
  let body;
  if(d.data.srcId!=null){ const ta=document.getElementById("src-"+d.data.srcId);
    body=(d.data.kind==="ref"?"// also shown in full elsewhere in the tree\n\n":"")+(ta?ta.value:"(source unavailable)"); }
  else { body=d.data.desc||""; }
  document.getElementById("side-code").textContent=body; side.classList.add("open");
}
document.getElementById("close").onclick=()=>side.classList.remove("open");

function fit(){
  const b=g.node().getBBox(), cw=chart.clientWidth, ch=chart.clientHeight;
  const s=Math.min(cw/(b.width+80), ch/(b.height+80), 1.4);
  const tx=(cw-(b.width+80)*s)/2 - (b.x-40)*s, ty=(ch-(b.height+80)*s)/2 - (b.y-40)*s;
  svg.transition().duration(400).call(zoom.transform, d3.zoomIdentity.translate(tx,ty).scale(s));
}
document.getElementById("btn-reset").onclick=()=>{ (root.children||root._children||[]).forEach(c=>{ c.children=c.children||c._children; }); root.children=root.children||root._children; root._children=null; (root.children||[]).forEach(collapse); update(root); setTimeout(fit,60); };
document.getElementById("btn-expand").onclick=()=>{ expandAll(root); update(root); setTimeout(fit,60); };
window.addEventListener("resize",fit);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
