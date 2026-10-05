"""DOM baseline hashing with per-region drift reports (stdlib only).

Idea: capture a trusted snapshot of each page from a clean run, then compare any
later snapshot region by region (form fields, links/actions, visible text,
comments). Drift in a protected field or a link to a new host is a strong,
INDEPENDENT signal that does not depend on keywords in page text.

Limits (state these in the dissertation)
- A baseline only exists for pages you captured; dynamic regions must be masked
  or approved, otherwise legitimate change looks like drift.
- It observes the HTML source, so attacks applied after the snapshot are missed.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlparse

from .signals import Signal

DEFAULT_MASK_PATTERNS = [
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?Z?\b",  # ISO timestamps
    r"\b[0-9a-fA-F]{24,}\b",                                       # long hex ids / nonces
]
DEFAULT_PROTECTED = ("origin", "destination", "cabin", "passenger", "date", "email",
                     "seat", "meal", "baggage", "insurance", "currency", "fare", "price")
_BLOCK = {"p", "div", "li", "ul", "ol", "tr", "td", "th", "table", "section", "article",
          "header", "footer", "nav", "main", "h1", "h2", "h3", "h4", "h5", "h6", "br",
          "form", "label", "button", "option", "select", "fieldset", "legend"}


@dataclass
class Snapshot:
    fields: Dict[str, dict] = field(default_factory=dict)
    links: List[List[str]] = field(default_factory=list)   # [kind, url]
    blocks: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)

    @staticmethod
    def from_json(s: str) -> "Snapshot":
        d = json.loads(s)
        return Snapshot(d["fields"], d["links"], d["blocks"], d["comments"])


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.snap = Snapshot()
        self._buf: List[str] = []
        self._skip = 0
        self._sel: Optional[str] = None
        self._opt: Optional[dict] = None
        self._sel_done = False
        self._ta: Optional[str] = None
        self._n = 0

    def _flush(self) -> None:
        text = " ".join("".join(self._buf).split())
        self._buf = []
        if text:
            self.snap.blocks.append(text)

    def handle_starttag(self, tag, attrs):
        a = {k: (v if v is not None else "") for k, v in attrs}
        if tag in ("script", "style"):
            if tag == "script" and a.get("src"):
                self.snap.links.append(["script", a["src"]])
            self._skip += 1
            return
        if tag in _BLOCK:
            self._flush()
        if tag == "a" and "href" in a:
            self.snap.links.append(["a", a["href"]])
        elif tag == "form":
            self.snap.links.append(["form", a.get("action", "")])
        elif tag == "iframe" and "src" in a:
            self.snap.links.append(["iframe", a["src"]])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.snap.links.append(["meta-refresh", a.get("content", "")])
        elif tag == "input":
            self._n += 1
            typ = a.get("type", "text").lower()
            key = a.get("name") or a.get("id") or f"input#{self._n}"
            if typ in ("checkbox", "radio"):
                key = f"{key}[{a.get('value', 'on')}]"
                self.snap.fields[key] = {"type": typ, "value": "checked" if "checked" in a else ""}
            else:
                self.snap.fields[key] = {"type": typ, "value": a.get("value", "")}
        elif tag == "select":
            self._n += 1
            self._sel = a.get("name") or a.get("id") or f"select#{self._n}"
            self._sel_done = False
            self.snap.fields[self._sel] = {"type": "select", "value": ""}
        elif tag == "option" and self._sel:
            self._opt = {"value": a.get("value"), "selected": "selected" in a, "text": ""}
        elif tag == "textarea":
            self._n += 1
            self._ta = a.get("name") or a.get("id") or f"textarea#{self._n}"
            self.snap.fields[self._ta] = {"type": "textarea", "value": ""}

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
            return
        if tag in _BLOCK:
            self._flush()
        if tag == "option" and self._opt is not None and self._sel:
            val = self._opt["value"] if self._opt["value"] is not None else self._opt["text"].strip()
            if self._opt["selected"] or not self._sel_done:
                self.snap.fields[self._sel]["value"] = val
            self._sel_done = True
            self._opt = None
        elif tag == "select":
            self._sel = None
        elif tag == "textarea":
            self._ta = None

    def handle_data(self, data):
        if self._skip:
            return
        if self._ta is not None:
            self.snap.fields[self._ta]["value"] += data
        elif self._opt is not None:
            self._opt["text"] += data
        else:
            self._buf.append(data)

    def handle_comment(self, data):
        t = " ".join(data.split())
        if t:
            self.snap.comments.append(t)

    def close(self):
        super().close()
        self._flush()


def _mask(text: str, patterns: Sequence[str]) -> str:
    for p in patterns:
        text = re.sub(p, "<MASK>", text)
    return text


def snapshot_html(html: str, mask_patterns: Sequence[str] = DEFAULT_MASK_PATTERNS,
                  mask_fields: Iterable[str] = ()) -> Snapshot:
    c = _Collector()
    c.feed(html)
    c.close()
    s = c.snap
    ignore = set(mask_fields)
    s.fields = {k: {"type": v["type"], "value": _mask(v["value"], mask_patterns)}
                for k, v in s.fields.items() if k not in ignore}
    s.blocks = [_mask(b, mask_patterns) for b in s.blocks]
    s.comments = [_mask(b, mask_patterns) for b in s.comments]
    s.links = [[k, _mask(u, mask_patterns)] for k, u in s.links]
    return s


def _h(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def region_hashes(s: Snapshot) -> Dict[str, str]:
    out = {f"field:{k}": _h(v) for k, v in sorted(s.fields.items())}
    out["links"] = _h(sorted(map(tuple, s.links)))
    out["text"] = _h(s.blocks)
    out["comments"] = _h(s.comments)
    out["page"] = _h(out)
    return out


@dataclass
class Drift:
    region: str
    kind: str          # changed | added | removed
    severity: str      # low | medium | high
    points: int
    detail: str


@dataclass
class DriftReport:
    drifts: List[Drift] = field(default_factory=list)

    @property
    def changed_regions(self) -> List[str]:
        return [d.region for d in self.drifts]

    @property
    def score(self) -> int:
        """max + 10 per extra drift of >=20 points, capped at 100 (raise-only signal)."""
        pts = sorted((d.points for d in self.drifts), reverse=True)
        if not pts:
            return 0
        return min(100, pts[0] + 10 * sum(1 for p in pts[1:] if p >= 20))

    @property
    def severity(self) -> str:
        order = {"low": 1, "medium": 2, "high": 3}
        return max((d.severity for d in self.drifts), key=lambda s: order[s], default="none")

    def to_signal(self) -> Signal:
        return Signal("dom_baseline_drift", self.score, self.severity,
                      [f"{d.region} {d.kind}: {d.detail}" for d in self.drifts])


def _host(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except ValueError:
        return ""


def compare(base: Snapshot, cur: Snapshot, protected: Sequence[str] = DEFAULT_PROTECTED,
            allowed_hosts: Iterable[str] = ()) -> DriftReport:
    rep = DriftReport()
    prot = [p.lower() for p in protected]
    is_prot = lambda key: any(p in key.lower() for p in prot)

    for k in sorted(set(base.fields) | set(cur.fields)):
        b, c = base.fields.get(k), cur.fields.get(k)
        if b is None:
            rep.drifts.append(Drift(f"field:{k}", "added", "high" if is_prot(k) else "medium",
                                    45 if is_prot(k) else 25, f"new field {k}={c['value']!r} ({c['type']})"))
        elif c is None:
            rep.drifts.append(Drift(f"field:{k}", "removed", "high" if is_prot(k) else "medium",
                                    45 if is_prot(k) else 25, f"field {k} removed"))
        elif b != c:
            rep.drifts.append(Drift(f"field:{k}", "changed", "high" if is_prot(k) else "medium",
                                    50 if is_prot(k) else 25, f"{k}: {b['value']!r} -> {c['value']!r}"))

    base_hosts = {_host(u) for _, u in base.links if _host(u)} | {h.lower() for h in allowed_hosts}
    bset = {tuple(x) for x in base.links}
    cset = {tuple(x) for x in cur.links}
    for kind, url in sorted(cset - bset):
        h = _host(url)
        if kind in ("script", "iframe", "meta-refresh") or (h and h not in base_hosts):
            rep.drifts.append(Drift("links", "added", "high", 60, f"new {kind} -> {url}"))
        elif kind == "form":
            rep.drifts.append(Drift("links", "changed", "medium", 30, f"form action -> {url}"))
        else:
            rep.drifts.append(Drift("links", "added", "low", 8, f"new {kind} -> {url}"))
    for kind, url in sorted(bset - cset):
        rep.drifts.append(Drift("links", "removed", "low", 8, f"removed {kind} -> {url}"))

    added = [b for b in cur.blocks if b not in base.blocks]
    removed = [b for b in base.blocks if b not in cur.blocks]
    if added:
        rep.drifts.append(Drift("text", "added", "medium", min(30, 10 * len(added)),
                                f"{len(added)} new text block(s): {added[0][:80]!r}"))
    if removed:
        rep.drifts.append(Drift("text", "removed", "low", min(15, 5 * len(removed)),
                                f"{len(removed)} text block(s) removed"))
    new_comments = [c for c in cur.comments if c not in base.comments]
    if new_comments:
        rep.drifts.append(Drift("comments", "added", "medium", 20,
                                f"new HTML comment: {new_comments[0][:80]!r}"))
    return rep


class BaselineStore:
    """SQLite store with versioning and an explicit 'approve drift' workflow."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        conn.execute("""CREATE TABLE IF NOT EXISTS dom_baselines(
            page TEXT NOT NULL, version INTEGER NOT NULL, created_at REAL NOT NULL,
            snapshot TEXT NOT NULL, hashes TEXT NOT NULL,
            approved_by TEXT, reason TEXT, PRIMARY KEY(page, version))""")
        conn.commit()

    def capture(self, page: str, html: str, approved_by: Optional[str] = None,
                reason: Optional[str] = None, **kw) -> int:
        snap = snapshot_html(html, **kw)
        row = self.conn.execute("SELECT MAX(version) FROM dom_baselines WHERE page=?", (page,)).fetchone()
        ver = (row[0] or 0) + 1
        self.conn.execute("INSERT INTO dom_baselines VALUES(?,?,?,?,?,?,?)",
                          (page, ver, time.time(), snap.to_json(),
                           json.dumps(region_hashes(snap)), approved_by, reason))
        self.conn.commit()
        return ver

    def latest(self, page: str) -> Optional[Snapshot]:
        r = self.conn.execute("SELECT snapshot FROM dom_baselines WHERE page=? ORDER BY version DESC LIMIT 1",
                              (page,)).fetchone()
        return Snapshot.from_json(r[0]) if r else None

    def compare_to_latest(self, page: str, html: str, **kw) -> Optional[DriftReport]:
        base = self.latest(page)
        if base is None:
            return None
        cmp_kw = {k: kw.pop(k) for k in ("protected", "allowed_hosts") if k in kw}
        return compare(base, snapshot_html(html, **kw), **cmp_kw)

    def approve_drift(self, page: str, html: str, approved_by: str, reason: str, **kw) -> int:
        if not approved_by or not reason.strip():
            raise ValueError("approved_by and a reason are required")
        return self.capture(page, html, approved_by=approved_by, reason=reason, **kw)
