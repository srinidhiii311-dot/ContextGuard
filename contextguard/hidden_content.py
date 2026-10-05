"""Hidden-content detection: text a human cannot see but an agent may read.

Two scanners
1. HIDDEN_SCAN_JS + scan_page(page): runs in the live browser (Playwright) and uses
   computed styles and bounding boxes, so it sees what is really rendered.
2. scan_html(html): static fallback for stored snapshots / unit tests (inline styles,
   `hidden` attribute, comments, aria-hidden). It cannot see external CSS.

Scoring is RAISE-ONLY: hidden text can add risk, never reduce it. Hidden text that
contains instruction language scores high; ordinary hidden UI (collapsed menus,
aria-hidden icons) scores low so benign pages are not blocked.
The instruction patterns are lexical: say so in the limitations section.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Sequence

from .signals import Signal

INSTRUCTION_PATTERNS: List[str] = [
    r"\b(ignore|disregard|forget|override)\b[^.]{0,60}\b(previous|prior|above|earlier|all|your)\b[^.]{0,30}\b(instructions?|rules?|prompt|constraints?)\b",
    r"\b(you (must|should|need to|are now)|new instructions?|system (message|prompt|notice))\b",
    r"\b(do not|don't|never)\b[^.]{0,30}\b(tell|inform|notify|mention|show|reveal)\b[^.]{0,20}\b(user|human)\b",
    r"\b(select|choose|change|set|switch)\b[^.]{0,40}\b(business|first class|premium|cheapest|upgrade)\b",
    r"\b(send|email|forward|post|upload)\b[^.]{0,60}\b(to|at)\b[^.]{0,40}(@|https?://)",
    r"\b(navigate|go|redirect|open)\b[^.]{0,20}\bto\b[^.]{0,20}https?://",
    r"\b(skip|bypass)\b[^.]{0,20}\b(review|confirmation|verification|payment)\b",
    r"\b(ai|assistant|agent|llm|model)\s*[,:]\s",
]

HIDDEN_SCAN_JS = r"""
(() => {
  const out = [];
  const bgOf = (el) => { while (el) { const c = getComputedStyle(el).backgroundColor;
      if (c && c !== 'rgba(0, 0, 0, 0)' && c !== 'transparent') return c; el = el.parentElement; }
      return 'rgb(255, 255, 255)'; };
  const sel = (el) => { if (el.id) return '#' + el.id; let s = el.tagName.toLowerCase();
      if (el.className && typeof el.className === 'string') s += '.' + el.className.trim().split(/\s+/).join('.');
      return s; };
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE']);
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (w.nextNode()) {
    const n = w.currentNode, t = (n.textContent || '').trim();
    const el = n.parentElement;
    if (!t || !el || SKIP.has(el.tagName)) continue;
    const reasons = [];
    for (let cur = el; cur && cur !== document.documentElement; cur = cur.parentElement) {
      const cs = getComputedStyle(cur);
      if (cs.display === 'none') { reasons.push('display:none'); break; }
      if (cs.visibility === 'hidden' || cs.visibility === 'collapse') { reasons.push('visibility:hidden'); break; }
      if (parseFloat(cs.opacity) === 0) { reasons.push('opacity:0'); break; }
      if (cur.hasAttribute('hidden')) { reasons.push('hidden-attribute'); break; }
    }
    const cs = getComputedStyle(el);
    if (!reasons.length) {
      const r = el.getBoundingClientRect();
      if (parseFloat(cs.fontSize) <= 1) reasons.push('font-size:~0');
      else if (r.width < 2 || r.height < 2) reasons.push('zero-size');
      else if (r.right + scrollX < 0 || r.bottom + scrollY < 0 ||
               r.left + scrollX > document.documentElement.scrollWidth + 50) reasons.push('off-screen');
      else if (parseFloat(cs.textIndent) < -999) reasons.push('text-indent');
      else if (cs.color === bgOf(el)) reasons.push('same-colour-as-background');
    }
    if (reasons.length) out.push({text: t.slice(0, 500), reason: reasons.join('+'), selector: sel(el)});
  }
  const cw = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
  while (cw.nextNode()) { const t = cw.currentNode.textContent.trim();
      if (t) out.push({text: t.slice(0, 500), reason: 'html-comment', selector: '<!-- -->'}); }
  document.querySelectorAll('[aria-label],[title],[alt],[data-instruction],[data-prompt]').forEach(el => {
    for (const a of ['aria-label', 'title', 'alt', 'data-instruction', 'data-prompt']) {
      const v = (el.getAttribute(a) || '').trim();
      if (v.length >= 25) out.push({text: v.slice(0, 500), reason: 'attr:' + a, selector: sel(el)});
    } });
  document.querySelectorAll('meta[name][content]').forEach(m => {
    const v = (m.getAttribute('content') || '').trim();
    if (v.length >= 25) out.push({text: v.slice(0, 500), reason: 'meta', selector: 'meta[' + m.name + ']'}); });
  return out;
})()
"""


def scan_page(page) -> List[Dict[str, str]]:
    """Sync Playwright page -> findings [{text, reason, selector}]."""
    return page.evaluate(HIDDEN_SCAN_JS)


async def scan_page_async(page) -> List[Dict[str, str]]:
    return await page.evaluate(HIDDEN_SCAN_JS)


_HIDE_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*(hidden|collapse)|opacity\s*:\s*0(\.0+)?\s*(;|$)|"
    r"font-size\s*:\s*0(px|pt|em|rem)?\s*(;|$)|(left|top|text-indent)\s*:\s*-\d{3,}", re.I)
_VOID = {"br", "hr", "img", "input", "meta", "link", "area", "base", "col", "source", "wbr"}


class _Static(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.findings: List[Dict[str, str]] = []
        self.stack: List[Optional[str]] = []   # hide reason per open element
        self.skip = 0

    def _reason(self) -> Optional[str]:
        for r in reversed(self.stack):
            if r:
                return r
        return None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self.skip += 1
            return
        for k in ("aria-label", "title", "alt", "data-instruction", "data-prompt"):
            if len(a.get(k, "").strip()) >= 25:
                self.findings.append({"text": a[k].strip()[:500], "reason": f"attr:{k}", "selector": tag})
        if tag == "meta" and len(a.get("content", "").strip()) >= 25 and a.get("name"):
            self.findings.append({"text": a["content"].strip()[:500], "reason": "meta", "selector": "meta"})
        if tag in _VOID:
            return
        reason = None
        if "hidden" in a:
            reason = "hidden-attribute"
        elif _HIDE_STYLE.search(a.get("style", "")):
            reason = "inline-style:" + _HIDE_STYLE.search(a["style"]).group(0).strip()
        elif a.get("aria-hidden", "").lower() == "true":
            reason = "aria-hidden"
        self.stack.append(reason)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        elif tag not in _VOID and self.stack:
            self.stack.pop()

    def handle_data(self, data):
        t = data.strip()
        if not t or self.skip:
            return
        r = self._reason()
        if r:
            self.findings.append({"text": t[:500], "reason": r, "selector": "static"})

    def handle_comment(self, data):
        t = " ".join(data.split())
        if t:
            self.findings.append({"text": t[:500], "reason": "html-comment", "selector": "<!-- -->"})


def scan_html(html: str) -> List[Dict[str, str]]:
    p = _Static()
    p.feed(html)
    p.close()
    return p.findings


@dataclass
class HiddenResult:
    score: int = 0
    severity: str = "none"
    hits: List[Dict[str, str]] = field(default_factory=list)      # instruction-bearing
    benign_hidden: int = 0

    def to_signal(self) -> Signal:
        ev = [f"{h['reason']} @ {h['selector']}: {h['text'][:80]!r}" for h in self.hits]
        return Signal("hidden_content", self.score, self.severity, ev)


def score_findings(findings: Iterable[Dict[str, str]],
                   patterns: Optional[Sequence[str]] = None) -> HiddenResult:
    pats = [re.compile(p, re.I) for p in (patterns or INSTRUCTION_PATTERNS)]
    res = HiddenResult()
    for f in findings:
        text = f.get("text", "")
        if any(p.search(text) for p in pats):
            res.hits.append(f)
        elif f.get("reason", "").startswith("aria-hidden"):
            continue                       # decorative icons etc.
        else:
            res.benign_hidden += 1
    if res.hits:
        res.score = min(100, 50 + 10 * (len(res.hits) - 1))
        res.severity = "high"
    elif res.benign_hidden:
        res.score = min(10, 3 * res.benign_hidden)
        res.severity = "low"
    return res
