"""
موتور تحلیل فاز اول: قوانین ساده و قابل‌توسعه از rules.yaml می‌خونه
و هر پورت باز رو به یک Finding تبدیل می‌کنه.

در فازهای بعدی، این فایل محل اتصال به CVE matching هم خواهد بود -
بدون اینکه ساختار Finding یا CLI نیاز به تغییر داشته باشه.
"""
from pathlib import Path

import yaml

from .models import Action, Finding, ScanMode, Severity
from .Nmap_scanner import OpenPort

DEFAULT_RULES_PATH = Path(__file__).parent / "rules.yaml"


class RuleEngine:
    def __init__(self, rules_path: Path = DEFAULT_RULES_PATH):
        with open(rules_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # ایندکس کردن قوانین بر اساس نام سرویس برای جستجوی سریع
        self._rules_by_service = {
            rule["match_service"].lower(): rule for rule in data["rules"]
        }
        self._default_rule = data["default_rule"]

    def analyze(self, target: str, open_ports: list[OpenPort]) -> list[Finding]:
        findings: list[Finding] = []
        for p in open_ports:
            rule = self._rules_by_service.get(p.service.lower())
            if rule:
                findings.append(self._finding_from_rule(target, p, rule))
            else:
                findings.append(self._finding_from_default(target, p))
        return findings

    def _finding_from_rule(self, target: str, p: OpenPort, rule: dict) -> Finding:
        return Finding(
            target=target,
            port=p.port,
            service=p.service,
            scan_mode=ScanMode.EXTERNAL,
            severity=Severity(rule["severity"]),
            title=rule["title"],
            recommendation=rule["recommendation"],
            action=Action(rule["action"]),
            rule_id=rule["id"],
            extra={"product": p.product, "version": p.version},
        )

    def _finding_from_default(self, target: str, p: OpenPort) -> Finding:
        r = self._default_rule
        return Finding(
            target=target,
            port=p.port,
            service=p.service,
            scan_mode=ScanMode.EXTERNAL,
            severity=Severity(r["severity"]),
            title=r["title_template"].format(service=p.service, port=p.port),
            recommendation=r["recommendation"],
            action=Action(r["action"]),
            rule_id="DEFAULT",
            extra={"product": p.product, "version": p.version},
        )