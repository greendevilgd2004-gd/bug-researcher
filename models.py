"""
مدل‌های داده مشترک پروژه.
هر نتیجه اسکن (چه حالت داخلی چه خارجی) در نهایت به یک Finding تبدیل می‌شه
تا موتور تحلیل و گزارش‌گیری بدون دونستن جزئیات منبع، باهاش کار کنن.
"""
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanMode(str, Enum):
    EXTERNAL = "external"   # بدون اعتبار، فقط از روی شبکه (شبیه دید مهاجم)
    INTERNAL = "internal"   # با اعتبار/SSH/WinRM، دید کامل از سیستم (برای فاز بعد)


class Action(str, Enum):
    CLOSE_PORT = "close_port"        # سرویس لازم نیست، ببند
    HARDEN = "harden"                # سرویس لازمه ولی باید امن‌تر تنظیم بشه
    UPDATE = "update"                # نسخه قدیمیه، آپدیت کن
    REVIEW = "review"                # نیاز به بررسی دستی داره


@dataclass
class Finding:
    target: str
    port: int
    service: str                 # مثلاً "ftp", "telnet", "mysql"
    scan_mode: ScanMode
    severity: Severity
    title: str                   # خلاصه یک‌خطی مشکل
    recommendation: str          # توصیه عملی قابل‌اجرا
    action: Action
    rule_id: str = ""            # کدوم قانون این finding رو تولید کرده
    extra: dict = field(default_factory=dict)  # اطلاعات اضافه (نسخه سرویس و...)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "scan_mode": self.scan_mode.value,
            "severity": self.severity.value,
            "title": self.title,
            "recommendation": self.recommendation,
            "action": self.action.value,
            "rule_id": self.rule_id,
            "extra": self.extra,
        }