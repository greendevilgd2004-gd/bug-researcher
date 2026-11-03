"""
نقطه ورود خط فرمان. فعلاً فقط حالت External (اسکن شبکه با nmap) فعاله.
نمونه استفاده:
    python -m scanner.cli 127.0.0.1
    python -m scanner.cli 127.0.0.1 --json
"""
import argparse
import json
import sys

from .models import Severity
from .Nmap_scanner import NmapNotFoundError, NmapScanner
from .Rule_engine import RuleEngine

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_LABEL_FA = {
    Severity.CRITICAL: "بحرانی",
    Severity.HIGH: "بالا",
    Severity.MEDIUM: "متوسط",
    Severity.LOW: "پایین",
    Severity.INFO: "اطلاعاتی",
}


def run(target: str) -> list:
    scanner = NmapScanner()
    open_ports = scanner.scan(target)
    engine = RuleEngine()
    findings = engine.analyze(target, open_ports)
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings


def print_report(target: str, findings: list) -> None:
    print(f"\n=== گزارش اسکن امنیتی: {target} ===\n")
    if not findings:
        print("هیچ پورت باز شناخته‌شده‌ای پیدا نشد.")
        return

    for f in findings:
        label = SEVERITY_LABEL_FA[f.severity]
        print(f"[{label}] پورت {f.port}/{f.service}  (قانون: {f.rule_id})")
        print(f"  مشکل   : {f.title}")
        print(f"  توصیه  : {f.recommendation}")
        print(f"  اقدام  : {f.action.value}")
        print()

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = " | ".join(
        f"{SEVERITY_LABEL_FA[s]}: {c}" for s, c in sorted(counts.items(), key=lambda x: SEVERITY_ORDER[x[0]])
    )
    print(f"خلاصه: {summary}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ابزار اسکن و توصیه امنیتی (فاز اول - حالت External)")
    parser.add_argument("target", help="آی‌پی یا هاست‌نیم هدف")
    parser.add_argument("--json", action="store_true", help="خروجی را به‌صورت JSON چاپ کن")
    args = parser.parse_args()

    try:
        findings = run(args.target)
    except NmapNotFoundError as e:
        print(f"خطا: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"خطا در اجرای اسکن: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2))
    else:
        print_report(args.target, findings)


if __name__ == "__main__":
    main()