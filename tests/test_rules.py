import ipaddress
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_rules  # noqa: E402

BLOCK_MODS = [
    "AdDomain", "Backdoor_Block", "Botnet_Block", "Malware_IOC_Block",
    "Pegasus_Block", "Phishing_Block", "Scam_Block", "Quarantine_Block",
]

CRITICAL_SAFE_DOMAINS = [
    "cole.best", "115.com", "115cdn.com", "115cdn.net",
    "themoviedb.org", "tmdb.org", "emby.media",
    "github.com", "raw.githubusercontent.com", "cloudflare.com",
    "workers.dev", "pages.dev", "vercel.app", "amazonaws.com", "cloudfront.net",
    "apple.com", "icloud.com", "qq.com", "weixin.qq.com", "bilibili.com", "hdslb.com",
    "dmm.co.jp", "openai.com", "anthropic.com", "claude.ai", "google.com", "googleapis.com",
]


class RulesetTestSuite(unittest.TestCase):
    def test_parse_rule_line_edge_cases(self):
        self.assertEqual(
            build_rules.parse_rule_line("DOMAIN-SUFFIX,Example.COM # a, b", "t.list", 1),
            ("DOMAIN-SUFFIX", "example.com"),
        )
        self.assertEqual(
            build_rules.parse_rule_line("IP-CIDR,1.2.3.4/24,no-resolve # comment", "t.list", 1),
            ("IP-CIDR", "1.2.3.0/24"),
        )
        self.assertEqual(
            build_rules.parse_rule_line("OMAIN-SUFFIX,typo.org", "t.list", 1),
            ("DOMAIN-SUFFIX", "typo.org"),
        )
        self.assertEqual(
            build_rules.parse_rule_line("DOMAIN-SUFFIX,update.xn—\u200b6frz82g", "t.list", 1),
            ("DOMAIN-SUFFIX", "update.xn--6frz82g"),
        )
        self.assertEqual(
            build_rules.parse_rule_line("DOMAIN-SUFFIX,.leading-and-trailing.com.", "t.list", 1),
            ("DOMAIN-SUFFIX", "leading-and-trailing.com"),
        )
        self.assertIsNone(build_rules.parse_rule_line("DOMAIN-SUFFIX,-bad-hyphen.com", "t.list", 1))
        self.assertIsNone(build_rules.parse_rule_line("DOMAIN-SUFFIX,double..dot.com", "t.list", 1))

    def test_generated_files_integrity(self):
        surge_files = list((ROOT / "surge").glob("*.list"))
        clash_files = list((ROOT / "clash").glob("*.yaml"))
        self.assertEqual(len(surge_files), 26)
        self.assertEqual(len(clash_files), 26)
        for cf in clash_files + list((ROOT / "clash" / "domain").glob("*.yaml")):
            lines = cf.read_text(encoding="utf-8").splitlines()
            self.assertIn("payload:", lines)
            for l in lines:
                if l and not l.startswith("#") and l != "payload:":
                    self.assertTrue(l.startswith("  - '") and l.endswith("'"), msg=f"Bad line in {cf}: {l}")
                    self.assertNotIn("IP-ASN,", l, msg=f"IP-ASN leaked into Clash YAML {cf}")

    def test_no_critical_false_positives_in_blocklists(self):
        blocked_suffixes: dict[str, set[str]] = {}
        for bm in BLOCK_MODS:
            s = set()
            for l in (ROOT / "surge" / f"{bm}.list").read_text(encoding="utf-8").splitlines():
                if l.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")):
                    s.add(l.split(",")[1])
            blocked_suffixes[bm] = s

        for dom in CRITICAL_SAFE_DOMAINS:
            parts = dom.split(".")
            ancestors = [".".join(parts[i:]) for i in range(len(parts))]
            for bm, bset in blocked_suffixes.items():
                overlap = set(ancestors) & bset
                self.assertFalse(overlap, msg=f"Critical domain {dom} blocked by {bm}: {overlap}")

    def test_no_cidr_overlap_between_blocklists_and_core_services(self):
        block_nets = []
        for bm in BLOCK_MODS:
            for l in (ROOT / "surge" / f"{bm}.list").read_text(encoding="utf-8").splitlines():
                if l.startswith(("IP-CIDR,", "IP-CIDR6,")):
                    block_nets.append((bm, ipaddress.ip_network(l.split(",")[1], strict=False)))
        for sm in ("OpenAI", "Google", "Telegram", "Apple", "WeChat", "China"):
            for l in (ROOT / "surge" / f"{sm}.list").read_text(encoding="utf-8").splitlines():
                if l.startswith(("IP-CIDR,", "IP-CIDR6,")):
                    snet = ipaddress.ip_network(l.split(",")[1], strict=False)
                    for bm, bnet in block_nets:
                        if bnet.version == snet.version:
                            self.assertFalse(bnet.overlaps(snet), msg=f"{bm}:{bnet} overlaps {sm}:{snet}")


    def test_no_upstream_coupling_and_domestic_cdn_clean(self):
        self.assertFalse((ROOT / ".github" / "workflows" / "sync-aegis.yml").exists())
        self.assertTrue((ROOT / "src" / "OpenAI.list").exists())
        proxy_text = (ROOT / "surge" / "Proxy.list").read_text(encoding="utf-8")
        for dom in ("huaweicloud.com", "myhuaweicloud.com", "sf-express.com", "tencent-cloud.com", "jd.com", "jd.hk"):
            self.assertNotIn(f",{dom}\n", proxy_text, msg=f"Domestic CDN {dom} still in Proxy.list")
        for p in [ROOT / "README.md", ROOT / "manifest.json", ROOT / ".github" / "workflows" / "ci.yml"]:
            self.assertNotIn("Thoseyearsbrian", p.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
