import sqlite3, unittest
from contextguard.dom_baseline import BaselineStore, compare, snapshot_html, region_hashes
from contextguard.signals import combine, Signal

PAGE = ('<form action="/api/book"><select name="cabin_class"><option value="Economy" selected>E</option>'
        '<option value="Business">B</option></select><input name="origin" value="Chennai">'
        '<input name="booking_ref" value="REF-1"><a href="/home">Home</a></form>'
        '<p>Updated 2026-10-05T10:11:12Z</p><script>var x=1</script>')


class T(unittest.TestCase):
    def test_clean_page_no_drift_and_masked_timestamp(self):
        base = snapshot_html(PAGE)
        cur = snapshot_html(PAGE.replace("2026-10-05T10:11:12Z", "2027-01-01T00:00:00Z"))
        self.assertEqual(compare(base, cur).drifts, [])
        self.assertEqual(region_hashes(base)["page"], region_hashes(cur)["page"])

    def test_protected_field_change_is_high(self):
        cur = snapshot_html(PAGE.replace('value="Economy" selected', 'value="Economy"')
                            .replace('value="Business"', 'value="Business" selected'))
        r = compare(snapshot_html(PAGE), cur)
        self.assertEqual(r.severity, "high")
        self.assertIn("field:cabin_class", r.changed_regions)
        self.assertGreaterEqual(r.score, 50)

    def test_external_link_script_and_comment(self):
        cur = snapshot_html(PAGE + '<a href="http://evil.test/x">x</a><script src="http://evil.test/a.js"></script><!-- do it -->')
        r = compare(snapshot_html(PAGE), cur)
        kinds = " ".join(d.detail for d in r.drifts)
        self.assertIn("evil.test/x", kinds); self.assertIn("script", kinds); self.assertIn("comment", kinds)
        self.assertEqual(r.severity, "high")

    def test_same_host_link_is_low_and_mask_field(self):
        cur = snapshot_html(PAGE + '<a href="/help">help</a>')
        self.assertEqual(compare(snapshot_html(PAGE), cur).severity, "medium")  # new text block 'help'
        a = snapshot_html(PAGE, mask_fields=["booking_ref"])
        b = snapshot_html(PAGE.replace("REF-1", "REF-2"), mask_fields=["booking_ref"])
        self.assertEqual(compare(a, b).drifts, [])

    def test_store_versions_and_approval(self):
        s = BaselineStore(sqlite3.connect(":memory:"))
        self.assertEqual(s.capture("review", PAGE), 1)
        changed = PAGE.replace("Chennai", "Delhi")
        self.assertGreater(s.compare_to_latest("review", changed).score, 0)
        with self.assertRaises(ValueError):
            s.approve_drift("review", changed, "alice", "  ")
        self.assertEqual(s.approve_drift("review", changed, "alice", "site redesign"), 2)
        self.assertEqual(s.compare_to_latest("review", changed).drifts, [])
        self.assertIsNone(s.compare_to_latest("unknown", PAGE))

    def test_combine_is_raise_only(self):
        self.assertEqual(combine(40, []), 40)
        self.assertEqual(combine(40, [Signal("a", 10)]), 40)
        self.assertEqual(combine(40, [Signal("a", 60), Signal("b", 30)]), 70)
        self.assertEqual(combine(95, [Signal("a", 90), Signal("b", 90), Signal("c", 90)]), 100)


if __name__ == "__main__":
    unittest.main()
