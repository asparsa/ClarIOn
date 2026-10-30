"""Render results/report_data.json into a self-contained HTML report.

Usage: python make_report.py [--data results/report_data.json] [--out report/index.html]
"""
import argparse
import json
import os

POS_FAMILIES = ["clean_spike", "multi_outlier", "subtle_shift", "drift"]
FAMILY_LABEL = {
    "clean_spike": "Clean spike",
    "multi_outlier": "Multi-outlier",
    "subtle_shift": "Subtle shift",
    "drift": "Gradual drift",
    "neg_control": "Negative control",
}
FAMILY_DESC = {
    "clean_spike": "one large outlier among normal calls",
    "multi_outlier": "3-5 spikes in the same function",
    "subtle_shift": "~1.7x elevation on ~20% of calls, near the band",
    "drift": "monotonic ramp to 3x over the series",
    "neg_control": "lognormal jitter only, no injected anomaly",
}
DET_ORDER = ["ClarIOn", "SSTD", "HBOS"]


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def derive(data):
    ops = data["ops"]

    def op(family, det, setting):
        for o in ops:
            if o["family"] == family and o["detector"] == det and o["setting"] == setting:
                return o
        return None

    # headline: mean F1 over the 4 positive families, default and F1-optimal
    tiles = {}
    for det in DET_ORDER:
        d = mean([op(f, det, "default")["f1"] for f in POS_FAMILIES
                  if op(f, det, "default")])
        o = mean([(op(f, det, "f1_opt") or op(f, det, "default"))["f1"]
                  for f in POS_FAMILIES])
        tiles[det] = {"default_f1": d, "f1opt_f1": o}
    return tiles, op


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(__file__)
    ap.add_argument("--data", default=os.path.join(here, "results", "report_data.json"))
    ap.add_argument("--out", default=os.path.join(here, "report", "index.html"))
    args = ap.parse_args()

    with open(args.data) as f:
        data = json.load(f)
    tiles, op = derive(data)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    payload = json.dumps({
        "curves": data["curves"], "ops": data["ops"], "scal": data["scal"],
        "familyLabel": FAMILY_LABEL, "familyDesc": FAMILY_DESC,
        "posFamilies": POS_FAMILIES, "detOrder": DET_ORDER, "tiles": tiles,
    }, separators=(",", ":"))

    with open(args.out, "w") as f:
        f.write(HTML.replace("/*__DATA__*/", payload))
    print("wrote", args.out, "(%.1f KB)" % (os.path.getsize(args.out) / 1024))


HTML = r"""<title>ClarIOn vs Chimbuko</title>
<meta name="claude:viewport-fit-sides" content="cover">
<style>
/* Layout: single analytical column; sticky header; small-multiple SVG charts. */
:root{
  --bg:#f6f7f9; --surface:#ffffff; --viz:#fcfcfb;
  --fg:#15171c; --muted:#5a616e; --faint:#8a909c;
  --border:#e4e7ec; --grid:#eef0f3;
  --accent:#2a78d6;
  --s-clarion:#2a78d6; --s-sstd:#eb6834; --s-hbos:#1baf7a;
  --good:#1a8f5a; --bad:#d64545;
  --sans:"IBM Plex Sans",system-ui,sans-serif;
  --disp:"Archivo",var(--sans);
  --mono:"IBM Plex Mono",ui-monospace,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#111318; --surface:#1a1d23; --viz:#191b1f;
  --fg:#eef0f3; --muted:#a9afba; --faint:#7b8290;
  --border:#2a2e37; --grid:#23262d;
  --accent:#3987e5;
  --s-clarion:#3987e5; --s-sstd:#e06a3a; --s-hbos:#22b584;
  --good:#3fb57e; --bad:#e8706f;
  color-scheme:dark;
}}
:root[data-theme="dark"]{
  --bg:#111318; --surface:#1a1d23; --viz:#191b1f;
  --fg:#eef0f3; --muted:#a9afba; --faint:#7b8290;
  --border:#2a2e37; --grid:#23262d;
  --accent:#3987e5;
  --s-clarion:#3987e5; --s-sstd:#e06a3a; --s-hbos:#22b584;
  --good:#3fb57e; --bad:#e8706f;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.55;
  font-size:15px;-webkit-font-smoothing:antialiased}
.wrap{max-width:960px;margin:0 auto;
  padding-left:max(18px,env(safe-area-inset-left,0px));
  padding-right:max(18px,env(safe-area-inset-right,0px))}
h1,h2,h3{font-family:var(--disp);font-weight:700;text-wrap:balance;line-height:1.15;margin:0}
h2{font-size:1.4rem;letter-spacing:-.01em;margin-bottom:.15em}
h3{font-size:1.02rem;font-weight:600}
p{margin:.5em 0}
.mono{font-family:var(--mono)}
.num{font-family:var(--mono);font-variant-numeric:tabular-nums}
a{color:var(--accent)}
header.top{position:sticky;top:env(safe-area-inset-top,0px);z-index:9;
  background:var(--bg);border-bottom:1px solid var(--border)}
body::before{content:"";position:fixed;inset:0 0 auto;height:env(safe-area-inset-top,0px);
  background:var(--bg);z-index:10}
header.top .wrap{display:flex;align-items:baseline;gap:.6rem;flex-wrap:wrap;padding-block:.7rem}
header.top .ey{font-family:var(--mono);font-size:.7rem;letter-spacing:.12em;text-transform:uppercase;
  color:var(--faint)}
header.top .nm{font-family:var(--disp);font-weight:700;font-size:1rem}
section{padding-block:1.6rem;border-bottom:1px solid var(--border)}
.lede{font-size:1.05rem;color:var(--fg)}
.sub{color:var(--muted);font-size:.92rem}
.eyebrow{font-family:var(--mono);font-size:.72rem;letter-spacing:.11em;text-transform:uppercase;
  color:var(--faint);margin-bottom:.5rem}
/* tiles */
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:1rem}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.tile .dname{display:flex;align-items:center;gap:.45rem;font-weight:600;font-size:.92rem}
.swatch{width:11px;height:11px;border-radius:3px;flex:none}
.tile .big{font-family:var(--mono);font-size:2.05rem;font-weight:500;line-height:1.1;margin-top:.35rem;
  font-variant-numeric:tabular-nums}
.tile .cap{font-size:.78rem;color:var(--muted)}
.tile .second{font-family:var(--mono);font-size:.82rem;color:var(--muted);margin-top:.35rem}
/* legend */
.legend{display:flex;gap:1.1rem;flex-wrap:wrap;align-items:center;margin:.3rem 0 1rem}
.legend .it{display:flex;align-items:center;gap:.4rem;font-size:.86rem}
.legend .mk{width:22px;height:0;border-top-width:3px;border-top-style:solid;border-radius:2px}
.hint{font-size:.8rem;color:var(--faint)}
/* charts grid */
.charts{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 12px 6px}
.panel h3{margin-bottom:.1rem}
.panel .pd{font-size:.78rem;color:var(--muted);margin-bottom:.3rem}
.panel svg{width:100%;height:auto;display:block;overflow:visible}
.svgwrap{min-width:0}
/* table */
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:.84rem}
th,td{padding:7px 10px;text-align:right;white-space:nowrap}
th:first-child,td:first-child{text-align:left}
thead th{font-family:var(--mono);font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);font-weight:500;border-bottom:1px solid var(--border)}
tbody td{font-family:var(--mono);font-variant-numeric:tabular-nums}
tbody td:first-child,tbody th:first-child{font-family:var(--sans)}
tr.grp td{background:var(--bg);font-family:var(--disp)!important;font-weight:600;text-align:left;
  color:var(--muted);font-size:.78rem;letter-spacing:.02em}
.det{display:inline-flex;align-items:center;gap:.4rem}
.miss{color:var(--bad)}
.q{color:var(--faint)}
/* tooltip */
#tip{position:fixed;pointer-events:none;z-index:50;background:var(--fg);color:var(--bg);
  font-family:var(--mono);font-size:.72rem;padding:5px 8px;border-radius:6px;opacity:0;
  transition:opacity .08s;max-width:240px;line-height:1.4}
.callout{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);
  border-radius:8px;padding:12px 14px;font-size:.9rem;margin-top:1rem}
ul.notes{margin:.4rem 0;padding-left:1.1rem}
ul.notes li{margin:.35rem 0;color:var(--fg);font-size:.9rem}
ul.notes li b{font-weight:600}
code{font-family:var(--mono);font-size:.85em;background:var(--grid);padding:.08em .35em;border-radius:4px}
footer{padding-block:1.4rem;color:var(--faint);font-size:.8rem}
@media(max-width:640px){.tiles{grid-template-columns:1fr}.charts{grid-template-columns:1fr}}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">

<header class="top"><div class="wrap">
  <span class="nm">ClarIOn vs Chimbuko</span>
  <span class="ey">anomaly detection &middot; precision / recall / scalability</span>
</div></header>

<div class="wrap">

<section>
  <div class="eyebrow">What this is</div>
  <p class="lede">A controlled comparison of ClarIOn's call-tree anomaly detector against
  Chimbuko's two primary detection algorithms, on identical synthetic traces with known
  ground truth.</p>
  <p class="sub">ClarIOn runs as its real <span class="mono">clarion_calltree --detect-anomaly</span>
  binary. Chimbuko is represented by faithful offline reimplementations of its documented
  algorithms: <b>SSTD</b> (per-function mean &plusmn; &alpha;&sigma;) and <b>HBOS</b>
  (per-function histogram-density score). Each injected operation is a leaf occurrence
  repeated 60 times under its own root, so the per-occurrence samples ClarIOn aggregates
  are byte-identical to what the Chimbuko scorers see. The evaluation unit is per function:
  flagged or not. Figures are means over 5 seeds &times; 100 functions, 30% of them anomalous.</p>
</section>

<section>
  <div class="eyebrow">Headline &mdash; F1 at out-of-the-box defaults</div>
  <p class="sub">Mean F1 across the four anomaly families, at each tool's default setting
  (ClarIOn 50% band, SSTD 6&sigma;, HBOS top-1%). The second line is the best F1 each tool
  can reach when its threshold is tuned per family.</p>
  <div class="tiles" id="tiles"></div>
</section>

<section>
  <div class="eyebrow">Precision &ndash; recall curves</div>
  <p class="sub">Each curve sweeps one tool's threshold. Up and to the right is better.
  <span class="mono">&#9679;</span> marks the default setting, <span class="mono">&#9632;</span>
  the F1-optimal point. Hover any marker for exact values.</p>
  <div class="legend" id="legend"></div>
  <div class="charts" id="prcharts"></div>
</section>

<section>
  <div class="eyebrow">False positives under noise</div>
  <p class="sub">The negative-control workload injects no anomalies &mdash; every flag is a
  false positive. Bars show the share of clean functions wrongly flagged at each tool's
  default setting.</p>
  <div class="panel" style="max-width:560px"><div class="svgwrap" id="fpchart"></div></div>
</section>

<section>
  <div class="eyebrow">Operating points</div>
  <p class="sub">Precision (P), recall (R), F1, and false-positive rate (FP) for every family.
  Recall is undefined for the negative control (no positives); FP is the relevant metric there.</p>
  <div class="tablewrap"><table id="optable"></table></div>
</section>

<section>
  <div class="eyebrow">Scalability</div>
  <p class="sub">Detection time versus trace size. ClarIOn is the C++ binary's
  detect-minus-aggregate wall-clock delta; SSTD and HBOS are the reference Python scorers.
  Absolute times are not comparable across a compiled binary and a Python prototype &mdash;
  read the slopes: every method is linear in event count (slope &asymp; 1 on log-log axes).</p>
  <div class="panel" style="max-width:640px"><div class="svgwrap" id="scalchart"></div></div>
  <div class="callout" id="scalnote"></div>
</section>

<section>
  <div class="eyebrow">How to read this, and what it does not cover</div>
  <ul class="notes">
    <li><b>Scope.</b> The workloads are per-function execution-time anomalies &mdash; the class
    both tools target. ClarIOn's subtree-shape "system" anomalies have no Chimbuko equivalent
    and are out of scope here.</li>
    <li><b>Offline algorithms, not the live system.</b> This compares detection logic on static
    traces. It does not exercise Chimbuko's real distributed runtime (ADIOS2 streaming, the
    parameter server's global model sync, the provenance database).</li>
    <li><b>Why SSTD collapses on multi-outlier and subtle-shift.</b> Its mean and &sigma; are
    built from all occurrences including the anomalies, so a cluster of outliers inflates the
    baseline until the outliers sit inside the 6&sigma; band. ClarIOn's median barely moves, so
    its percentage band stays anchored.</li>
    <li><b>Why HBOS over-flags.</b> As a univariate per-function histogram with a global score
    cutoff, a lone-sample tail bin in a normal function scores like a real spike, so precision
    stays low. HBOS is built for high-dimensional feature outliers, not single-series durations.</li>
    <li><b>Time basis.</b> ClarIOn compares inclusive duration; Chimbuko defaults to exclusive.
    The leaf occurrences here make the two identical, removing that variable.</li>
  </ul>
  <p class="sub" style="margin-top:1rem">Reproduce: <code>python run_compare.py --funcs 100 --k 60 --seeds 5</code>
  then <code>python make_report.py</code>. Harness and CSVs live in
  <code>benchmarks/anomaly_compare/</code>.</p>
</section>

</div>
<div class="wrap"><footer>Synthetic ground-truth benchmark. ClarIOn detector = production binary;
SSTD / HBOS = reference reimplementations of the published Chimbuko algorithms.</footer></div>

<div id="tip"></div>

<script>
const DATA = /*__DATA__*/;
const SC = {ClarIOn:"var(--s-clarion)",SSTD:"var(--s-sstd)",HBOS:"var(--s-hbos)"};
const NS="http://www.w3.org/2000/svg";
const tip=document.getElementById("tip");
function el(t,a){const e=document.createElementNS(NS,t);for(const k in(a||{}))e.setAttribute(k,a[k]);return e;}
function showTip(html,ev){tip.innerHTML=html;tip.style.opacity=1;
  let x=ev.clientX+12,y=ev.clientY+12;
  if(x+tip.offsetWidth>innerWidth)x=ev.clientX-tip.offsetWidth-12;
  if(y+tip.offsetHeight>innerHeight)y=ev.clientY-tip.offsetHeight-12;
  tip.style.left=x+"px";tip.style.top=y+"px";}
function hideTip(){tip.style.opacity=0;}
const pct=v=>v==null?"&ndash;":(v*100).toFixed(0)+"%";
const pct1=v=>v==null?"&ndash;":(v*100).toFixed(1)+"%";

/* ---- PR curve small multiple ---- */
function prPanel(fam){
  const W=430,H=330,m={l:52,r:14,t:12,b:44};
  const pw=W-m.l-m.r,ph=H-m.t-m.b;
  const X=r=>m.l+r*pw, Y=p=>m.t+(1-p)*ph;
  const svg=el("svg",{viewBox:`0 0 ${W} ${H}`,role:"img"});
  // grid + axes
  for(let i=0;i<=4;i++){
    const gx=m.l+i/4*pw, gy=m.t+i/4*ph;
    svg.appendChild(el("line",{x1:gx,y1:m.t,x2:gx,y2:m.t+ph,stroke:"var(--grid)","stroke-width":1}));
    svg.appendChild(el("line",{x1:m.l,y1:gy,x2:m.l+pw,y2:gy,stroke:"var(--grid)","stroke-width":1}));
    const tx=el("text",{x:m.l+i/4*pw,y:m.t+ph+16,"text-anchor":"middle",
      fill:"var(--faint)","font-size":10,"font-family":"var(--mono)"});
    tx.textContent=(i/4).toFixed(2);svg.appendChild(tx);
    const ty=el("text",{x:m.l-8,y:m.t+i/4*ph+3.5,"text-anchor":"end",
      fill:"var(--faint)","font-size":10,"font-family":"var(--mono)"});
    ty.textContent=(1-i/4).toFixed(2);svg.appendChild(ty);
  }
  // axis titles
  const axx=el("text",{x:m.l+pw/2,y:H-6,"text-anchor":"middle",fill:"var(--muted)","font-size":11});
  axx.textContent="recall";svg.appendChild(axx);
  const axy=el("text",{x:14,y:m.t+ph/2,"text-anchor":"middle",fill:"var(--muted)","font-size":11,
    transform:`rotate(-90 14 ${m.t+ph/2})`});axy.textContent="precision";svg.appendChild(axy);
  // frame
  svg.appendChild(el("rect",{x:m.l,y:m.t,width:pw,height:ph,fill:"none",stroke:"var(--border)","stroke-width":1}));
  const ops=DATA.ops.filter(o=>o.family===fam);
  DATA.detOrder.forEach(det=>{
    const pts=(DATA.curves[fam][det]||[]).filter(p=>p.recall!=null&&p.precision!=null)
      .slice().sort((a,b)=>a.recall-b.recall);
    if(pts.length){
      let d="";pts.forEach((p,i)=>{d+=(i?"L":"M")+X(p.recall)+" "+Y(p.precision);});
      svg.appendChild(el("path",{d,fill:"none",stroke:SC[det],"stroke-width":2,
        "stroke-linejoin":"round","stroke-linecap":"round","opacity":.9}));
      pts.forEach(p=>{
        const c=el("circle",{cx:X(p.recall),cy:Y(p.precision),r:5,fill:"transparent"});
        c.addEventListener("mousemove",e=>showTip(
          `<b>${det}</b> &middot; ${DATA.familyLabel[fam]}<br>param ${p.param}<br>`+
          `P ${pct1(p.precision)} &middot; R ${pct(p.recall)}<br>F1 ${p.f1==null?"&ndash;":p.f1.toFixed(2)}`,e));
        c.addEventListener("mouseleave",hideTip);svg.appendChild(c);
        svg.appendChild(el("circle",{cx:X(p.recall),cy:Y(p.precision),r:1.6,fill:SC[det]}));
      });
    }
    // operating markers
    ops.filter(o=>o.detector===det).forEach(o=>{
      if(o.recall==null||o.precision==null)return;
      const x=X(o.recall),y=Y(o.precision),def=o.setting==="default";
      let mk;
      if(def)mk=el("circle",{cx:x,cy:y,r:5.2,fill:SC[det],stroke:"var(--surface)","stroke-width":1.8});
      else mk=el("rect",{x:x-4.6,y:y-4.6,width:9.2,height:9.2,fill:SC[det],
        stroke:"var(--surface)","stroke-width":1.8});
      mk.addEventListener("mousemove",e=>showTip(
        `<b>${det}</b> &middot; ${def?"default":"F1-optimal"} (${o.param})<br>`+
        `P ${pct1(o.precision)} &middot; R ${pct(o.recall)}<br>F1 ${o.f1==null?"&ndash;":o.f1.toFixed(2)} `+
        `&middot; FP ${pct1(o.fp_rate)}`,e));
      mk.addEventListener("mouseleave",hideTip);svg.appendChild(mk);
    });
  });
  return svg;
}

/* ---- FP bar chart ---- */
function fpChart(){
  const W=540,H=200,m={l:70,r:20,t:10,b:34};
  const pw=W-m.l-m.r,ph=H-m.t-m.b;
  const svg=el("svg",{viewBox:`0 0 ${W} ${H}`,role:"img"});
  const rows=DATA.detOrder.map(det=>{
    const o=DATA.ops.find(o=>o.family==="neg_control"&&o.detector===det&&o.setting==="default");
    return {det,fp:o?o.fp_rate:0,param:o?o.param:""};});
  for(let i=0;i<=4;i++){const gx=m.l+i/4*pw;
    svg.appendChild(el("line",{x1:gx,y1:m.t,x2:gx,y2:m.t+ph,stroke:"var(--grid)","stroke-width":1}));
    const tx=el("text",{x:gx,y:m.t+ph+16,"text-anchor":"middle",fill:"var(--faint)",
      "font-size":10,"font-family":"var(--mono)"});tx.textContent=(i/4*100)+"%";svg.appendChild(tx);}
  const bh=22,gap=(ph-rows.length*bh)/(rows.length+1);
  rows.forEach((r,i)=>{
    const y=m.t+gap+i*(bh+gap);
    const lb=el("text",{x:m.l-10,y:y+bh/2+4,"text-anchor":"end",fill:"var(--fg)","font-size":12,
      "font-family":"var(--sans)"});lb.textContent=r.det;svg.appendChild(lb);
    svg.appendChild(el("rect",{x:m.l,y,width:pw,height:bh,fill:"var(--grid)",rx:3}));
    const w=Math.max(2,r.fp*pw);
    const bar=el("rect",{x:m.l,y,width:w,height:bh,fill:SC[r.det],rx:3});
    bar.addEventListener("mousemove",e=>showTip(`<b>${r.det}</b> default (${r.param})<br>`+
      `false positives: ${pct1(r.fp)} of clean functions`,e));
    bar.addEventListener("mouseleave",hideTip);svg.appendChild(bar);
    const vl=el("text",{x:m.l+w+6,y:y+bh/2+4,fill:"var(--muted)","font-size":11,
      "font-family":"var(--mono)"});vl.textContent=pct1(r.fp);svg.appendChild(vl);
  });
  const axx=el("text",{x:m.l+pw/2,y:H-4,"text-anchor":"middle",fill:"var(--muted)","font-size":11});
  axx.textContent="false-positive rate (lower is better)";svg.appendChild(axx);
  document.getElementById("fpchart").appendChild(svg);
}

/* ---- scalability log-log ---- */
function scalChart(){
  const pts=DATA.scal.filter(d=>d.time_ms>0);
  const W=620,H=340,m={l:62,r:16,t:14,b:46};
  const pw=W-m.l-m.r,ph=H-m.t-m.b;
  const xs=pts.map(p=>p.events),ys=pts.map(p=>p.time_ms);
  const xmin=Math.log10(900),xmax=Math.log10(1.1e6);
  const ymin=Math.log10(1),ymax=Math.log10(2200);
  const X=e=>m.l+(Math.log10(e)-xmin)/(xmax-xmin)*pw;
  const Y=t=>m.t+(1-(Math.log10(t)-ymin)/(ymax-ymin))*ph;
  const svg=el("svg",{viewBox:`0 0 ${W} ${H}`,role:"img"});
  [3,4,5,6].forEach(e=>{const gx=X(Math.pow(10,e));
    svg.appendChild(el("line",{x1:gx,y1:m.t,x2:gx,y2:m.t+ph,stroke:"var(--grid)","stroke-width":1}));
    const tx=el("text",{x:gx,y:m.t+ph+16,"text-anchor":"middle",fill:"var(--faint)","font-size":10,
      "font-family":"var(--mono)"});tx.textContent="1e"+e;svg.appendChild(tx);});
  [1,10,100,1000].forEach(t=>{const gy=Y(t);
    svg.appendChild(el("line",{x1:m.l,y1:gy,x2:m.l+pw,y2:gy,stroke:"var(--grid)","stroke-width":1}));
    const ty=el("text",{x:m.l-8,y:gy+3.5,"text-anchor":"end",fill:"var(--faint)","font-size":10,
      "font-family":"var(--mono)"});ty.textContent=(t>=1000?"1 s":t+" ms");svg.appendChild(ty);});
  svg.appendChild(el("rect",{x:m.l,y:m.t,width:pw,height:ph,fill:"none",stroke:"var(--border)","stroke-width":1}));
  DATA.detOrder.forEach(det=>{
    const dp=pts.filter(p=>p.detector===det).sort((a,b)=>a.events-b.events);
    if(!dp.length)return;
    let d="";dp.forEach((p,i)=>{d+=(i?"L":"M")+X(p.events)+" "+Y(p.time_ms);});
    svg.appendChild(el("path",{d,fill:"none",stroke:SC[det],"stroke-width":2,
      "stroke-linejoin":"round","stroke-linecap":"round"}));
    dp.forEach(p=>{
      const c=el("circle",{cx:X(p.events),cy:Y(p.time_ms),r:4.5,fill:SC[det],
        stroke:"var(--surface)","stroke-width":1.4});
      c.addEventListener("mousemove",e=>showTip(`<b>${det}</b><br>${p.events.toLocaleString()} events<br>`+
        `${p.time_ms.toFixed(1)} ms`+(p.throughput?`<br>${(p.throughput/1e6).toFixed(2)}M ev/s`:""),e));
      c.addEventListener("mouseleave",hideTip);svg.appendChild(c);
    });
  });
  const axx=el("text",{x:m.l+pw/2,y:H-6,"text-anchor":"middle",fill:"var(--muted)","font-size":11});
  axx.textContent="events in trace (log scale)";svg.appendChild(axx);
  const axy=el("text",{x:14,y:m.t+ph/2,"text-anchor":"middle",fill:"var(--muted)","font-size":11,
    transform:`rotate(-90 14 ${m.t+ph/2})`});axy.textContent="detection time (log scale)";svg.appendChild(axy);
  document.getElementById("scalchart").appendChild(svg);
}

/* ---- tiles ---- */
function tiles(){
  const box=document.getElementById("tiles");
  DATA.detOrder.forEach(det=>{
    const t=DATA.tiles[det];
    const d=document.createElement("div");d.className="tile";
    d.innerHTML=`<div class="dname"><span class="swatch" style="background:${SC[det]}"></span>${det}</div>`+
      `<div class="big">${t.default_f1==null?"&ndash;":t.default_f1.toFixed(2)}</div>`+
      `<div class="cap">mean F1 at default</div>`+
      `<div class="second">tuned best: ${t.f1opt_f1==null?"&ndash;":t.f1opt_f1.toFixed(2)}</div>`;
    box.appendChild(d);
  });
}
/* ---- legend ---- */
function legend(){
  const L=document.getElementById("legend");
  DATA.detOrder.forEach(det=>{
    const s=document.createElement("span");s.className="it";
    s.innerHTML=`<span class="mk" style="border-top-color:${SC[det]}"></span>${det}`;
    L.appendChild(s);
  });
  const note=document.createElement("span");note.className="hint";
  note.innerHTML="&#9679; default &nbsp; &#9632; F1-optimal";L.appendChild(note);
}
/* ---- PR charts ---- */
function prCharts(){
  const box=document.getElementById("prcharts");
  DATA.posFamilies.forEach(fam=>{
    const p=document.createElement("div");p.className="panel";
    p.innerHTML=`<h3>${DATA.familyLabel[fam]}</h3><div class="pd">${DATA.familyDesc[fam]}</div>`;
    const w=document.createElement("div");w.className="svgwrap";w.appendChild(prPanel(fam));
    p.appendChild(w);box.appendChild(p);
  });
}
/* ---- operating-point table ---- */
function table(){
  const t=document.getElementById("optable");
  t.innerHTML="<thead><tr><th>Detector</th><th>Setting</th><th>P</th><th>R</th><th>F1</th><th>FP</th></tr></thead>";
  const tb=document.createElement("tbody");
  const fams=DATA.posFamilies.concat(["neg_control"]);
  fams.forEach(fam=>{
    const g=document.createElement("tr");g.className="grp";
    g.innerHTML=`<td colspan="6">${DATA.familyLabel[fam]} &middot; ${DATA.familyDesc[fam]}</td>`;tb.appendChild(g);
    DATA.detOrder.forEach(det=>{
      ["default","f1_opt"].forEach(setting=>{
        const o=DATA.ops.find(o=>o.family===fam&&o.detector===det&&o.setting===setting);
        if(!o)return;
        const tr=document.createElement("tr");
        const r=o.recall, miss=(r!=null&&r<0.05)?' class="miss"':'';
        tr.innerHTML=`<td><span class="det"><span class="swatch" style="background:${SC[det]}"></span>${det}</span></td>`+
          `<td class="q">${setting==="default"?"default":"tuned"} (${o.param})</td>`+
          `<td>${pct1(o.precision)}</td>`+
          `<td${miss}>${o.recall==null?'<span class="q">&ndash;</span>':pct(o.recall)}</td>`+
          `<td>${o.f1==null?'<span class="q">&ndash;</span>':o.f1.toFixed(2)}</td>`+
          `<td>${pct1(o.fp_rate)}</td>`;
        tb.appendChild(tr);
      });
    });
  });
  t.appendChild(tb);
}
/* ---- scalability note ---- */
function scalNote(){
  const c=DATA.scal.find(d=>d.detector==="ClarIOn"&&d.events>900000);
  const s=DATA.scal.find(d=>d.detector==="SSTD"&&d.events>900000);
  const h=DATA.scal.find(d=>d.detector==="HBOS"&&d.events>900000);
  document.getElementById("scalnote").innerHTML=
    `At ~1 million events, ClarIOn's detection step adds <b>${(c.time_ms/1000).toFixed(2)} s</b> `+
    `(the C++ binary, measured as detect minus aggregate). The reference Python SSTD and HBOS `+
    `scorers take <b>${(s.time_ms/1000).toFixed(2)} s</b> and <b>${(h.time_ms/1000).toFixed(2)} s</b> `+
    `on the same samples. All three are linear in event count; the gap is implementation and `+
    `language, not algorithmic order. Below ~10&#8201;000 events ClarIOn's delta sits under `+
    `measurement noise, so only the two larger sizes are plotted for it.`;
}

tiles();legend();prCharts();fpChart();table();scalChart();scalNote();
</script>
"""

if __name__ == "__main__":
    main()
