# SecScan (فاز اول - MVP)

ابزار اسکن امنیتی که به‌جای فقط نمایش پورت‌های باز، برای هرکدوم توصیه‌ی عملی
(بستن پورت / سخت‌سازی / بررسی) ارائه می‌ده.

## وضعیت فعلی این فاز
- فقط **حالت External** (اسکن شبکه بدون اعتبار، با nmap) فعاله.
- قوانین در `scanner/rules.yaml` تعریف شدن و بدون نیاز به تغییر کد قابل افزایشن.
- CVE matching و حالت Internal (SSH/WinRM) هنوز اضافه نشدن — فازهای بعدی.

## نصب
```bash
sudo apt install nmap        # اگه نصب نیست
pip install -r requirements.txt --break-system-packages
```

## اجرا
```bash
python3 -m scanner.cli 192.168.1.10
python3 -m scanner.cli 192.168.1.10 --json
```

## افزودن قانون جدید
فقط یک آیتم جدید به `scanner/rules.yaml` اضافه کن:
```yaml
  - id: "MY-RULE"
    match_service: "nama-sarvis-dar-nmap"
    severity: "medium"
    title: "..."
    recommendation: "..."
    action: "harden"   # یا close_port / update / review
```

## ساختار پروژه
```
scanner/
  models.py        # مدل داده مشترک (Finding, Severity, Action, ScanMode)
  nmap_scanner.py   # لایه اسکن شبکه (wrapper روی nmap)
  rule_engine.py    # تطبیق پورت‌های باز با قوانین
  rules.yaml        # قوانین قابل‌ویرایش بدون نیاز به کد
  cli.py            # رابط خط فرمان
```

## گام بعدی پیشنهادی
بعد از تست این بخش، لایه‌ی Internal/Credentialed (اتصال SSH به لینوکس برای
بررسی عمقی‌تر پیکربندی) رو روی همین پایه اضافه می‌کنیم.
