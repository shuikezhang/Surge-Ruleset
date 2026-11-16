#!/usr/bin/env python3
"""
Standalone Surge & Clash/Mihomo Ruleset Compiler.

Maintains `src/*.list` as the single source of truth and compiles:
- `surge/*.list`           (Surge RULE-SET)
- `surge/domainset/*.list` (Surge DOMAIN-SET for pure-domain modules)
- `clash/*.yaml`           (Clash / Mihomo classical rule-provider)
- `clash/domain/*.yaml`    (Clash / Mihomo domain rule-provider for pure-domain modules)
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import re
import sys

TYPO_FIXES = {
    "OMAIN-SUFFIX": "DOMAIN-SUFFIX",
    "OMAIN": "DOMAIN",
    "OMAIN-KEYWORD": "DOMAIN-KEYWORD",
}

SUPPORTED_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
}

DOMAIN_RE = re.compile(r"^[a-z0-9_.-]+$", re.IGNORECASE)


def parse_rule_line(raw: str, source_file: str, lineno: int) -> tuple[str, str] | None:
    line = raw.split("#", 1)[0].strip()
    if not line or line.startswith("//") or line.startswith(";"):
        return None
    parts = [p.strip() for p in line.split(",") if p.strip()]
    if len(parts) < 2:
        raise ValueError(f"{source_file}:{lineno}: malformed rule line: {raw!r}")
    rtype = TYPO_FIXES.get(parts[0].upper(), parts[0].upper())
    val = parts[1]
    if rtype not in SUPPORTED_RULE_TYPES:
        raise ValueError(f"{source_file}:{lineno}: unsupported rule type {rtype!r} in {raw!r}")

    if rtype in ("DOMAIN", "DOMAIN-SUFFIX"):
        val = re.sub(r"[\u200b-\u200f\ufeff]", "", val)
        val = val.replace("xn\u2014", "xn--").replace("xn\u2013", "xn--")
        val = val.strip().strip(".").lower()
        if any(ord(ch) > 127 for ch in val):
            try:
                val = val.encode("idna").decode("ascii")
            except UnicodeError:
                print(f"WARN {source_file}:{lineno}: skipping invalid IDN {val!r}", file=sys.stderr)
                return None
        labels = val.split(".") if val else []
        valid_labels = (
            bool(labels)
            and len(val) <= 253
            and DOMAIN_RE.match(val) is not None
            and all(1 <= len(lb) <= 63 and not lb.startswith("-") and not lb.endswith("-") for lb in labels)
        )
        if not valid_labels:
            print(f"WARN {source_file}:{lineno}: skipping invalid domain {val!r}", file=sys.stderr)
            return None
    elif rtype == "DOMAIN-KEYWORD":
        val = val.lower()
        if not val:
            raise ValueError(f"{source_file}:{lineno}: empty DOMAIN-KEYWORD")
    elif rtype == "IP-CIDR":
        net = ipaddress.ip_network(val, strict=False)
        if net.version != 4:
            rtype = "IP-CIDR6"
        val = str(net)
    elif rtype == "IP-CIDR6":
        net = ipaddress.ip_network(val, strict=False)
        if net.version != 6:
            rtype = "IP-CIDR"
        val = str(net)
    elif rtype == "IP-ASN":
        if not val.isdigit():
            raise ValueError(f"{source_file}:{lineno}: invalid IP-ASN {val!r}")
    return rtype, val


def deduplicate(entries: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for item in entries:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def yaml_quote(s: str) -> str:
    escaped = s.replace("\\", "\\\\").replace("'", "''")
    return f"'{escaped}'"


def write_outputs(repo_root: pathlib.Path, module_name: str, entries: list[tuple[str, str]]) -> dict:
    entries = deduplicate(entries)
    if not entries:
        raise ValueError(f"Module {module_name} produced 0 entries")

    surge_dir = repo_root / "surge"
    surge_ds_dir = repo_root / "surge" / "domainset"
    clash_dir = repo_root / "clash"
    clash_dom_dir = repo_root / "clash" / "domain"
    for d in (surge_dir, surge_ds_dir, clash_dir, clash_dom_dir):
        d.mkdir(parents=True, exist_ok=True)

    header = [f"# shuikezhang/Surge-Ruleset | Module: {module_name}"]

    # 1. Surge RULE-SET (.list)
    surge_lines = list(header)
    for rtype, val in entries:
        if rtype in ("IP-CIDR", "IP-CIDR6", "IP-ASN"):
            surge_lines.append(f"{rtype},{val},no-resolve")
        else:
            surge_lines.append(f"{rtype},{val}")
    (surge_dir / f"{module_name}.list").write_text("\n".join(surge_lines) + "\n", encoding="utf-8")

    # 2. Clash/Mihomo classical (.yaml)
    clash_lines = [
        f"# shuikezhang/Surge-Ruleset | Module: {module_name} (classical)",
        "payload:",
    ]
    clash_count = 0
    for rtype, val in entries:
        if rtype == "IP-ASN":
            continue
        if rtype in ("IP-CIDR", "IP-CIDR6"):
            clash_lines.append(f"  - {yaml_quote(f'{rtype},{val},no-resolve')}")
        else:
            clash_lines.append(f"  - {yaml_quote(f'{rtype},{val}')}")
        clash_count += 1
    if clash_count == 0:
        raise ValueError(f"Module {module_name} produced 0 Clash entries")
    (clash_dir / f"{module_name}.yaml").write_text("\n".join(clash_lines) + "\n", encoding="utf-8")

    # 3. Pure-domain fast sets (Surge DOMAIN-SET + Clash behavior: domain)
    pure_domain = all(rt in ("DOMAIN", "DOMAIN-SUFFIX") for rt, _ in entries)
    if pure_domain:
        ds_lines = list(header)
        cd_lines = [
            f"# shuikezhang/Surge-Ruleset | Module: {module_name} (domain)",
            "payload:",
        ]
        for rtype, val in entries:
            if rtype == "DOMAIN-SUFFIX":
                ds_lines.append(f".{val}")
                cd_lines.append(f"  - {yaml_quote(f'+.{val}')}")
            else:
                ds_lines.append(val)
                cd_lines.append(f"  - {yaml_quote(val)}")
        (surge_ds_dir / f"{module_name}.list").write_text("\n".join(ds_lines) + "\n", encoding="utf-8")
        (clash_dom_dir / f"{module_name}.yaml").write_text("\n".join(cd_lines) + "\n", encoding="utf-8")

    return {
        "surge_rules": len(entries),
        "clash_classical_rules": clash_count,
        "pure_domain_set": pure_domain,
    }


def verify_outputs(repo_root: pathlib.Path, stats: dict[str, dict]) -> None:
    core_minimums = {
        "China": 500,
        "Proxy": 1000,
        "Google": 50,
        "OpenAI": 100,
        "Apple": 40,
        "Telegram": 15,
        "WeChat": 30,
        "Lan": 20,
    }
    for mod, min_cnt in core_minimums.items():
        if mod not in stats or stats[mod]["clash_classical_rules"] < min_cnt:
            raise RuntimeError(f"Sanity check failed for {mod}: {stats.get(mod)}")

    for yf in sorted((repo_root / "clash").rglob("*.yaml")):
        lines = yf.read_text(encoding="utf-8").splitlines()
        payload_idx = [i for i, l in enumerate(lines) if l == "payload:"]
        if len(payload_idx) != 1:
            raise RuntimeError(f"{yf}: missing unique payload: header")
        items = [l for l in lines[payload_idx[0] + 1 :] if l.strip()]
        if not items or not all(l.startswith("  - '") and l.endswith("'") for l in items):
            raise RuntimeError(f"{yf}: malformed YAML payload items")


def build_readme(repo_root: pathlib.Path, stats: dict[str, dict]) -> None:
    rows = []
    base = "https://raw.githubusercontent.com/shuikezhang/Surge-Ruleset/main"
    for name in sorted(stats.keys()):
        st = stats[name]
        s_url = f"[surge/{name}.list]({base}/surge/{name}.list)"
        c_url = f"[clash/{name}.yaml]({base}/clash/{name}.yaml)"
        ds_url = (
            f"[domainset]({base}/surge/domainset/{name}.list) / [clash-domain]({base}/clash/domain/{name}.yaml)"
            if st["pure_domain_set"]
            else "—"
        )
        rows.append(f"| `{name}` | {st['surge_rules']} | {s_url} | {c_url} | {ds_url} |")

    readme = "\n".join(
        [
            "# Surge & Clash Ruleset",
            "",
            "独立维护的 **Surge**（`RULE-SET` / `DOMAIN-SET`）与 **Clash / Mihomo**（`classical` / `domain`）双端分流与安全拦截规则库。",
            "",
            "## 维护方式",
            "",
            "1. 直接编辑 `src/<Module>.list` 源文件（唯一真值源）；",
            "2. 本地运行 `python3 scripts/build_rules.py --verify`（或直接提交推送 `src/*.list`，由 GitHub Actions `.github/workflows/ci.yml` 自动重编译双端产物并运行防误杀单测）。",
            "",
            "## 规则模块清单",
            "",
            "| 模块 | 规则数 | Surge (`RULE-SET`) | Clash / Mihomo (`classical`) | 纯域名高速集 (`DOMAIN-SET` / `domain`) |",
            "|---|---:|---|---|---|",
            *rows,
            "",
        ]
    )
    (repo_root / "README.md").write_text(readme, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="src", help="Source rules directory (default: src)")
    ap.add_argument("--out", default=".", help="Repository root directory (default: .)")
    ap.add_argument("--verify", action="store_true", help="Run post-build sanity & format checks")
    args = ap.parse_args()

    repo_root = pathlib.Path(args.out).resolve()
    src_dir = (repo_root / args.src).resolve() if not pathlib.Path(args.src).is_absolute() else pathlib.Path(args.src)
    if not src_dir.is_dir():
        raise SystemExit(f"Source directory not found: {src_dir}")

    stats: dict[str, dict] = {}
    for list_file in sorted(src_dir.glob("*.list")):
        mod_name = list_file.stem
        entries: list[tuple[str, str]] = []
        for idx, raw in enumerate(list_file.read_text(encoding="utf-8").splitlines(), 1):
            parsed = parse_rule_line(raw, list_file.name, idx)
            if parsed is not None:
                entries.append(parsed)
        stats[mod_name] = write_outputs(repo_root, mod_name, entries)

    if args.verify:
        verify_outputs(repo_root, stats)

    manifest = {
        "module_count": len(stats),
        "modules": stats,
    }
    (repo_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    build_readme(repo_root, stats)
    print(f"Built & verified {len(stats)} standalone modules from {src_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
