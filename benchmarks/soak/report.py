#!/usr/bin/env python3
"""Turn soak JSONL (see README.md) into summary.md and a self-contained report.html.

    report.py --rules rules.json --out DIR file.jsonl...

Exit code: 0 all gates held, 1 an impl listed in `gate_impls` broke a rule, 2 unusable input.
Python 3 standard library only.
"""
import argparse
import html
import json
import math
import os
import sys
from bisect import bisect_right
from collections import defaultdict

DEFAULTS = {
    "gate_impls": [],
    "warmup_min": 15,
    "window_min": 20,
    "freeze_rate_ratio_max": 2.0,
    "freeze_rate_abs_slack_per_min": 0.5,
    "audio_gap_ratio_max": 2.0,
    "audio_gap_abs_slack_pct": 0.5,
    "rss_slope_mb_per_h_max": 30,
    "rss_slope_min_span_min": 30,
    "min_clean_window_min": 5,
    "stall_max_s": 10,
    "recover_max_s": 10,
}
SAMPLE_S = 5  # seconds between samples
RECOVER_SETTLE_S = 15  # the start of `recover` is the outage's own aftermath, not steady state
COUNTERS = ("frames", "freezes", "freeze_ms", "packets", "lost", "nack", "pli", "audio_gap_ms")
PALETTE = ["#2563eb", "#dc2626", "#059669", "#d97706", "#7c3aed", "#0891b2", "#db2777", "#65a30d"]
PHASE_FILL = {"loss": "#facc15", "burst": "#fb923c", "bw": "#60a5fa", "outage": "#ef4444"}


class Run:
    def __init__(self, path):
        self.path = path
        self.stem = os.path.splitext(os.path.basename(path))[0]
        self.rows = []
        self.bad = 0
        self.t0 = 0.0
        self.t1 = 0.0
        self.phases = []  # (t seconds from t0, name)
        self.pt = []

    def finish(self):
        if not self.rows:
            return
        self.t0 = min(r["ts"] for r in self.rows) / 1000.0
        self.t1 = max(r["ts"] for r in self.rows) / 1000.0
        for r in self.rows:
            r["t"] = r["ts"] / 1000.0 - self.t0
        ph = sorted((r["t"], str(r.get("name"))) for r in self.rows if r["kind"] == "phase")
        self.phases = ph
        self.pt = [p[0] for p in ph]

    def phase_at(self, t):
        i = bisect_right(self.pt, t) - 1
        if i < 0:
            return ("clean", 0.0) if not self.pt else ("pre", 0.0)
        return self.phases[i][1], self.phases[i][0]

    def cleanish(self, group, t):
        if group == "clean" or not self.pt:
            return True
        name, start = self.phase_at(t)
        return name == "clean" or (name == "recover" and t - start >= RECOVER_SETTLE_S)


class Series:
    def __init__(self, label, impl, run, kind, sid):
        self.label, self.impl, self.run, self.kind, self.id = label, impl, run, kind, sid
        self.s = []
        self.media = None
        self.group = "impaired"
        self.regress = 0
        self.ivs = []

    def build(self):
        self.s.sort(key=lambda r: r["t"])
        if self.kind != "recv":
            return
        for a, b in zip(self.s, self.s[1:]):
            dt = b["t"] - a["t"]
            if dt <= 0:
                continue
            iv = {"t": b["t"], "dt": dt, "jitter": b.get("jitter_ms"), "rtt": b.get("rtt_ms")}
            for k in COUNTERS:
                d = (b.get(k) or 0) - (a.get(k) or 0)
                if d < 0:
                    if k != "lost":
                        self.regress += 1
                    d = 0
                iv[k] = d
            iv["phase"] = self.run.phase_at(b["t"])[0]
            iv["clean"] = self.run.cleanish(self.group, a["t"]) and self.run.cleanish(self.group, b["t"])
            self.ivs.append(iv)


def load(paths):
    runs = []
    for p in paths:
        r = Run(p)
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    r.bad += 1
                    continue
                if not (isinstance(o, dict) and isinstance(o.get("ts"), (int, float)) and "kind" in o):
                    r.bad += 1
                    continue
                r.rows.append(o)
        r.finish()
        runs.append(r)
    return runs


def build_series(runs):
    archs = defaultdict(set)
    files = defaultdict(set)
    for r in runs:
        for o in r.rows:
            if o["kind"] in ("recv", "proc", "dc", "event") and o.get("impl"):
                archs[o["impl"]].add(str(o.get("arch", "unknown")))
                files[(o["impl"], str(o.get("arch", "unknown")))].add(r.stem)

    def label_of(o, r):
        impl, arch = str(o.get("impl", "?")), str(o.get("arch", "unknown"))
        label = impl
        if len(archs[impl]) > 1:
            label += " " + arch
        if len(files[(impl, arch)]) > 1:
            label += " [%s]" % r.stem
        return label

    series = {}
    events = defaultdict(lambda: defaultdict(int))
    for r in runs:
        for o in r.rows:
            k = o["kind"]
            if k not in ("recv", "proc", "dc", "event"):
                continue
            impl = str(o.get("impl", "?"))
            label = label_of(o, r)
            if k == "event":
                events[label][str(o.get("what", "?"))] += 1
                continue
            key = (label, r.stem, k, str(o.get("id", "")))
            if key not in series:
                series[key] = Series(label, impl, r, k, key[3])
            s = series[key]
            s.s.append(o)
            if k == "recv":
                s.media = o.get("media", s.media)
                s.group = o.get("group", s.group)
    out = list(series.values())
    for s in out:
        s.build()
    return out, events


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def per_track_rate(sers, field, scale, pred, media):
    rates = []
    for s in sers:
        if s.kind != "recv" or s.media != media:
            continue
        ivs = [i for i in s.ivs if pred(i)]
        dt = sum(i["dt"] for i in ivs)
        if dt > 0:
            rates.append(sum(i[field] for i in ivs) * scale / dt)
    return mean(rates)


def metrics(sers, pred, tpred):
    """Metrics for one label over the intervals that pass pred (recv) and the samples that pass tpred(run, t)."""
    recv = [s for s in sers if s.kind == "recv"]
    ivs = [i for s in recv for i in s.ivs if pred(i)]
    pk = sum(i["packets"] for i in ivs)
    lost = sum(i["lost"] for i in ivs)
    m = {
        "freeze_rate": per_track_rate(recv, "freezes", 60, pred, "video"),
        "freeze_ms": per_track_rate(recv, "freeze_ms", 60, pred, "video"),
        "audio_gap": per_track_rate(recv, "audio_gap_ms", 0.1, pred, "audio"),
        "loss": 100.0 * lost / (pk + lost) if pk + lost else None,
        "clean_s": mean([sum(i["dt"] for i in s.ivs if pred(i)) for s in recv]),
        "jitter": mean([i["jitter"] for i in ivs]),
        "rtt": mean([i["rtt"] for i in ivs]),
        "nack": per_track_rate(recv, "nack", 1, pred, "video"),
        "pli": per_track_rate(recv, "pli", 60, pred, "video"),
    }
    dcs = [r for s in sers if s.kind == "dc" for r in s.s if tpred(s.run, r["t"])]
    m["dc_p50"] = mean([r.get("lat_ms_p50") for r in dcs])
    m["dc_p99"] = mean([r.get("lat_ms_p99") for r in dcs])
    procs = [r for s in sers if s.kind == "proc" for r in s.s if tpred(s.run, r["t"])]
    m["rss"] = mean([r.get("rss_mb") for r in procs])
    m["cpu"] = mean([r.get("cpu_pct") for r in procs])
    m["threads"] = max([r.get("threads") or 0 for r in procs], default=None)
    m["fds"] = max([r.get("fds") or 0 for r in procs], default=None)
    return m


def slope_mb_per_h(s, t_from):
    pts = [(r["t"] / 3600.0, r["rss_mb"]) for r in s.s if r["t"] >= t_from and r.get("rss_mb") is not None]
    if len(pts) < 3:
        return None, 0.0
    n = len(pts)
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    den = sum((p[0] - mx) ** 2 for p in pts)
    if den == 0:
        return None, 0.0
    return sum((p[0] - mx) * (p[1] - my) for p in pts) / den, (pts[-1][0] - pts[0][0]) * 60.0


def stalls(s):
    """Stall episodes outside outage: list of (start t, duration s).

    A `stalled` sample means media stopped for more than 2 s somewhere in the 5 s before it, so an
    episode lasts from its first stalled sample to its last, plus one sample interval. An episode
    whose first window overlaps an outage is the outage's aftermath (see recoveries), not a stall.
    """
    out, ep = [], None

    def excused(t):
        if s.group == "clean" or not s.run.pt:
            return False
        if s.run.phase_at(t)[0] == "outage" or s.run.phase_at(t - SAMPLE_S)[0] == "outage":
            return True
        return any(name == "outage" and t - SAMPLE_S < pt <= t for pt, name in s.run.phases)

    for r in s.s:
        if r.get("stalled"):
            if ep is None:
                ep = [r["t"], r["t"], excused(r["t"])]
            else:
                ep[1] = r["t"]
        elif ep is not None:
            if not ep[2]:
                out.append((ep[0], ep[1] - ep[0] + SAMPLE_S))
            ep = None
    if ep is not None and not ep[2]:
        out.append((ep[0], ep[1] - ep[0] + SAMPLE_S))
    return out


def recoveries(s, rules):
    """Seconds from each outage's end until frames grow again (inf = never); impaired tracks only."""
    out = []
    if s.group == "clean" or s.kind != "recv":
        return out
    ph = s.run.phases
    for i, (t, name) in enumerate(ph):
        if name != "outage" or i + 1 >= len(ph):
            continue
        end = ph[i + 1][0]
        prev = None
        got = None
        for r in s.s:
            if prev is not None and r["t"] > end and prev["t"] >= t and (r.get("frames") or 0) > (prev.get("frames") or 0):
                got = r["t"] - end
                break
            prev = r
        if got is not None:
            out.append(got)
        elif s.s and s.s[-1]["t"] - end >= rules["recover_max_s"]:
            out.append(math.inf)
    return out


def fmt(v, nd=2, unit=""):
    if v is None:
        return "-"
    if isinstance(v, float) and math.isinf(v):
        return "never"
    return ("%.*f" % (nd, v)) + unit


ROWS = [
    ("Freezes / min (video)", "freeze_rate", 2),
    ("Freeze ms / min (video)", "freeze_ms", 0),
    ("Audio gap %", "audio_gap", 2),
    ("Loss %", "loss", 2),
    ("Jitter ms", "jitter", 2),
    ("RTT ms", "rtt", 1),
    ("NACK / s (video)", "nack", 2),
    ("PLI / min (video)", "pli", 2),
    ("Data channel p50 ms", "dc_p50", 1),
    ("Data channel p99 ms", "dc_p99", 1),
    ("RSS MB", "rss", 1),
    ("CPU %", "cpu", 1),
    ("Threads (max)", "threads", 0),
    ("FDs (max)", "fds", 0),
]


def analyse(runs, rules):
    sers, events = build_series(runs)
    by_label = defaultdict(list)
    for s in sers:
        by_label[s.label].append(s)
    labels = sorted(by_label)
    res = {"labels": labels, "impl": {}, "windows": {}, "phase": {}, "slope": {}, "stalls": {}, "recov": {},
           "events": {}, "regress": {}, "span": {}, "checks": []}
    for lb in labels:
        sers_l = by_label[lb]
        res["impl"][lb] = sers_l[0].impl
        span = max(r.t1 - r.t0 for r in {s.run for s in sers_l})
        res["span"][lb] = span
        tot = span / 60.0
        warm = min(rules["warmup_min"], tot / 6.0) * 60.0
        win = min(rules["window_min"], tot / 4.0) * 60.0
        w_first = (warm, warm + win)
        w_last = (span - win, span)
        res["windows"][lb] = {"first": w_first, "last": w_last}
        for name, (a, b) in (("first", w_first), ("last", w_last)):
            res["windows"][lb][name + "_m"] = metrics(
                sers_l, lambda i, a=a, b=b: i["clean"] and a <= i["t"] <= b, lambda run, t, a=a, b=b: a <= t <= b and run.cleanish("impaired", t))
        names = sorted({i["phase"] for s in sers_l for i in s.ivs if s.group != "clean"})
        res["phase"][lb] = {
            n: metrics(sers_l, lambda i, n=n: i["phase"] == n, lambda run, t: False) for n in names}
        slopes = [slope_mb_per_h(s, warm) for s in sers_l if s.kind == "proc"]
        sl = [x for x, _ in slopes if x is not None]
        res["slope"][lb] = (max(sl) if sl else None, max([sp for _, sp in slopes], default=0.0))
        st = [e for s in sers_l if s.kind == "recv" for e in stalls(s)]
        res["stalls"][lb] = (len(st), max([d for _, d in st], default=0.0))
        rc = [x for s in sers_l for x in recoveries(s, rules)]
        res["recov"][lb] = (len(rc), max(rc, default=None))
        res["regress"][lb] = sum(s.regress for s in sers_l)
        res["events"][lb] = dict(events[lb])
        res["checks"] += check(lb, res, rules)
    return res, sers


def check(lb, res, rules):
    out = []
    impl = res["impl"][lb]
    gated = impl in rules["gate_impls"]
    f, l = res["windows"][lb]["first_m"], res["windows"][lb]["last_m"]

    def add(rule, value, limit, ok):
        status = "n/a" if ok is None else ("PASS" if ok else ("FAIL" if gated else "breach"))
        out.append({"label": lb, "impl": impl, "gated": gated, "rule": rule, "value": value, "limit": limit,
                    "status": status})

    for rule, key, ratio, slack in (
            ("freeze rate (last <= first x ratio + slack)", "freeze_rate", rules["freeze_rate_ratio_max"],
             rules["freeze_rate_abs_slack_per_min"]),
            ("audio gap % (last <= first x ratio + slack)", "audio_gap", rules["audio_gap_ratio_max"],
             rules["audio_gap_abs_slack_pct"])):
        a, b = f[key], l[key]
        need = rules["min_clean_window_min"] * 60
        if (f["clean_s"] or 0) < need or (l["clean_s"] or 0) < need:
            add(rule, "clean time first %s s, last %s s" % (fmt(f["clean_s"], 0), fmt(l["clean_s"], 0)),
                "needs %s min each" % rules["min_clean_window_min"], None)
        elif a is None or b is None:
            add(rule, "first %s, last %s" % (fmt(a), fmt(b)), "-", None)
        else:
            lim = a * ratio + slack
            add(rule, "first %s, last %s" % (fmt(a), fmt(b)), "<= %s" % fmt(lim), b <= lim)
    sl, span = res["slope"][lb]
    if sl is None or span < rules["rss_slope_min_span_min"]:
        add("RSS slope MB/h", "%s over %s min" % (fmt(sl, 1), fmt(span, 0)),
            "needs %s min" % rules["rss_slope_min_span_min"], None)
    else:
        add("RSS slope MB/h", fmt(sl, 1), "<= %s" % rules["rss_slope_mb_per_h_max"], sl <= rules["rss_slope_mb_per_h_max"])
    n, worst = res["stalls"][lb]
    add("longest stall outside outage s", "%d stalls, longest %s" % (n, fmt(worst, 1)),
        "<= %s" % rules["stall_max_s"], worst <= rules["stall_max_s"])
    n, worst = res["recov"][lb]
    if n == 0:
        add("recovery after outage s", "no outage seen", "-", None)
    else:
        add("recovery after outage s", "%d tracks, worst %s" % (n, fmt(worst, 1)),
            "<= %s" % rules["recover_max_s"], worst <= rules["recover_max_s"])
    return out


def tables(res):
    """List of (title, header, rows) shared by the markdown and html renderers."""
    labels = res["labels"]
    out = []
    rows = []
    for title, key, nd in ROWS:
        rows.append([title] + ["%s -> %s" % (fmt(res["windows"][lb]["first_m"][key], nd),
                                              fmt(res["windows"][lb]["last_m"][key], nd)) for lb in labels])
    rows.append(["RSS slope MB/h"] + [fmt(res["slope"][lb][0], 1) for lb in labels])
    out.append(("Clean-phase drift: first window -> last window", ["Metric"] + labels, rows))
    w = ["%s: %.1f-%.1f min -> %.1f-%.1f min" % ((lb,) + tuple(x / 60.0 for x in
         res["windows"][lb]["first"] + res["windows"][lb]["last"])) for lb in labels]
    out.append(("Windows (after warmup, clean phases only)", ["Window"], [[x] for x in w]))
    rows = [["Stalls outside outage (count / longest s)"] + ["%d / %s" % (res["stalls"][lb][0], fmt(res["stalls"][lb][1], 1)) for lb in labels],
            ["Outage recoveries (tracks / worst s)"] + ["%d / %s" % (res["recov"][lb][0], fmt(res["recov"][lb][1], 1)) for lb in labels],
            ["Counter regressions"] + [str(res["regress"][lb]) for lb in labels],
            ["Run length min"] + [fmt(res["span"][lb] / 60.0, 1) for lb in labels]]
    for what in ("wrap", "ice_state", "join", "leave", "error"):
        rows.append(["Events: " + what] + [str(res["events"][lb].get(what, 0)) for lb in labels])
    out.append(("Stalls, recovery and events", ["Measure"] + labels, rows))
    names = [n for n in ("clean", "loss", "burst", "bw", "outage", "recover")
             if any(n in res["phase"][lb] for lb in labels)]
    rows = []
    for n in names:
        for title, key, nd in ROWS[:8]:
            rows.append(["%s: %s" % (n, title)] + [fmt(res["phase"][lb].get(n, {}).get(key), nd) for lb in labels])
    out.append(("Per phase (whole run)", ["Phase: metric"] + labels, rows))
    rows = [[c["label"], c["rule"], c["value"], c["limit"], c["status"] + ("" if c["gated"] else " (not gated)" if c["status"] != "n/a" else "")]
            for c in res["checks"]]
    out.append(("Rules", ["Impl", "Rule", "Value", "Limit", "Result"], rows))
    return out


def markdown(res, rules, failed):
    lines = ["# Soak report", "",
             "Gated impls: %s. **%s**" % (", ".join(rules["gate_impls"]) or "none", "GATE FAILED" if failed else "gates held"), ""]
    for title, head, rows in tables(res):
        lines += ["## " + title, "", "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        lines += ["| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in rows]
        lines.append("")
    return "\n".join(lines)


def chart_series(sers, res, kind_metric, bin_s):
    """{label: [(minute, value)]} for one metric, binned."""
    acc = defaultdict(lambda: defaultdict(lambda: [0.0, 0.0]))
    for s in sers:
        a = acc[s.label]
        if s.kind == "recv":
            for i in s.ivs:
                b = int(i["t"] // bin_s)
                num, den = None, None
                dt = i["dt"]
                if kind_metric == "freeze_rate" and s.media == "video":
                    num, den = i["freezes"], dt / 60.0
                elif kind_metric == "freeze_ms" and s.media == "video":
                    num, den = i["freeze_ms"], dt / 60.0
                elif kind_metric == "audio_gap" and s.media == "audio":
                    num, den = i["audio_gap_ms"], dt * 10.0
                elif kind_metric == "loss":
                    num, den = i["lost"] * 100.0, i["packets"] + i["lost"]
                elif kind_metric == "jitter" and i["jitter"] is not None:
                    num, den = i["jitter"], 1
                elif kind_metric == "rtt" and i["rtt"] is not None:
                    num, den = i["rtt"], 1
                elif kind_metric == "nack" and s.media == "video":
                    num, den = i["nack"], dt
                elif kind_metric == "pli" and s.media == "video":
                    num, den = i["pli"], dt / 60.0
                if num is not None:
                    a[b][0] += num
                    a[b][1] += den
        else:
            field = {"dc_p50": "lat_ms_p50", "dc_p99": "lat_ms_p99", "rss": "rss_mb", "cpu": "cpu_pct",
                     "threads": "threads", "fds": "fds"}.get(kind_metric)
            if field is None or s.kind != ("dc" if kind_metric.startswith("dc") else "proc"):
                continue
            for r in s.s:
                if r.get(field) is not None:
                    b = int(r["t"] // bin_s)
                    a[b][0] += r[field]
                    a[b][1] += 1
    return {lb: [((b + 0.5) * bin_s / 60.0, v[0] / v[1]) for b, v in sorted(a.items()) if v[1] > 0]
            for lb, a in acc.items() if a}


def svg_chart(title, data, labels, colors, phases, span_min):
    W, H, L, R, T, B = 860, 220, 54, 12, 22, 28
    ymax = max([y for pts in data.values() for _, y in pts], default=0) * 1.1 or 1.0
    xs = lambda x: L + (W - L - R) * x / span_min
    ys = lambda y: T + (H - T - B) * (1 - y / ymax)
    o = ['<svg viewBox="0 0 %d %d" role="img" aria-label="%s">' % (W, H, html.escape(title)),
         '<text x="%d" y="14" class="t">%s</text>' % (L, html.escape(title))]
    for i, (t, name) in enumerate(phases):
        if name in PHASE_FILL:
            end = phases[i + 1][0] if i + 1 < len(phases) else span_min * 60
            x0, x1 = xs(t / 60.0), xs(end / 60.0)
            o.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="%s" opacity="0.22"/>' % (
                x0, T, max(x1 - x0, 1.0), H - T - B, PHASE_FILL[name]))
    for k in range(5):
        y = ymax * k / 4
        o.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" class="g"/><text x="%d" y="%.1f" class="a" text-anchor="end">%s</text>'
                 % (L, W - R, ys(y), ys(y), L - 4, ys(y) + 3, ("%.3g" % y)))
    for k in range(7):
        x = span_min * k / 6
        o.append('<text x="%.1f" y="%d" class="a" text-anchor="middle">%.0f</text>' % (xs(x), H - 10, x))
    o.append('<text x="%d" y="%d" class="a" text-anchor="end">minutes</text>' % (W - R, H - 1))
    for lb in labels:
        pts = data.get(lb)
        if pts:
            o.append('<polyline fill="none" stroke="%s" stroke-width="1.5" points="%s"/>' % (
                colors[lb], " ".join("%.1f,%.1f" % (xs(x), ys(y)) for x, y in pts)))
    o.append("</svg>")
    return "".join(o)


def html_report(res, sers, runs, rules, failed):
    labels = res["labels"]
    colors = {lb: PALETTE[i % len(PALETTE)] for i, lb in enumerate(labels)}
    span = max(res["span"].values()) / 60.0 or 1.0
    bin_s = max(5, int(math.ceil(span * 60 / 240 / 5.0) * 5))
    ref = max(runs, key=lambda r: len(r.phases))
    parts = ["<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
             "<title>Soak report</title><style>"
             ":root{--bg:#fff;--fg:#111;--mut:#666;--grid:#ddd;--bd:#ccc}"
             "@media(prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--mut:#999;--grid:#333;--bd:#444}}"
             "body{background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif;margin:0 auto;max-width:900px;padding:0 16px 40px}"
             "table{border-collapse:collapse;margin:8px 0 24px;display:block;overflow-x:auto}td,th{border:1px solid var(--bd);padding:3px 8px;text-align:left}"
             "svg{width:100%;height:auto;margin:6px 0}.t{fill:var(--fg);font-size:12px;font-weight:600}.a{fill:var(--mut);font-size:10px}"
             ".g{stroke:var(--grid);stroke-width:1}.k{display:inline-block;width:12px;height:3px;margin:0 4px 3px 12px}"
             ".sw{display:inline-block;width:10px;height:10px;margin:0 4px -1px 12px;opacity:.5}"
             ".f{color:#dc2626;font-weight:600}</style>",
             "<h1>Soak report</h1><p class=%s>Gated impls: %s. %s</p><p>" % (
                 '"f"' if failed else '"m"', html.escape(", ".join(rules["gate_impls"]) or "none"),
                 "GATE FAILED" if failed else "Gates held.")]
    parts += ['<span class=k style="background:%s"></span>%s' % (colors[lb], html.escape(lb)) for lb in labels]
    parts += ['<span class=sw style="background:%s"></span>%s' % (c, n) for n, c in PHASE_FILL.items()]
    parts.append("</p>")
    for title, key, _ in ROWS:
        data = chart_series(sers, res, key, bin_s)
        if data:
            parts.append(svg_chart(title, data, labels, colors, ref.phases, span))
    for title, head, rows in tables(res):
        parts.append("<h2>%s</h2><table><tr>%s</tr>%s</table>" % (
            html.escape(title), "".join("<th>%s</th>" % html.escape(h) for h in head),
            "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % html.escape(str(c)) for c in r) for r in rows)))
    parts.append("</html>")
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    rules = dict(DEFAULTS)
    with open(a.rules) as f:
        rules.update(json.load(f))
    runs = load(a.files)
    if not any(r.rows for r in runs):
        print("report.py: no usable samples in the input", file=sys.stderr)
        return 2
    for r in runs:
        if r.bad:
            print("report.py: %s: skipped %d malformed lines" % (r.path, r.bad), file=sys.stderr)
    res, sers = analyse(runs, rules)
    if not res["labels"]:
        print("report.py: no recv/proc/dc samples in the input", file=sys.stderr)
        return 2
    failed = any(c["status"] == "FAIL" for c in res["checks"])
    os.makedirs(a.out, exist_ok=True)
    md = markdown(res, rules, failed)
    with open(os.path.join(a.out, "summary.md"), "w") as f:
        f.write(md)
    with open(os.path.join(a.out, "report.html"), "w") as f:
        f.write(html_report(res, sers, runs, rules, failed))
    for c in res["checks"]:
        if c["status"] in ("FAIL", "breach"):
            print("%s %s: %s (%s, limit %s)" % (c["status"], c["label"], c["rule"], c["value"], c["limit"]), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
