"""
لایه اسکن شبکه (External / بدون اعتبار).
فعلاً یک wrapper ساده روی باینری nmap هست. در آینده اگه خواستیم جایگزینش کنیم
(مثلاً با موتور اسکن اختصاصی)، فقط کافیه یک کلاس دیگه با همین متد scan()
بنویسیم - بقیه پروژه تغییری نمی‌کنه.
"""
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class OpenPort:
    port: int
    protocol: str   # tcp/udp
    service: str    # نام سرویس شناسایی‌شده توسط nmap، مثلاً "ftp"
    product: str    # نام نرم‌افزار (اگه nmap بتونه تشخیص بده)
    version: str    # نسخه (اگه قابل تشخیص باشه)


class NmapNotFoundError(RuntimeError):
    pass


class NmapScanner:
    """
    اسکن پورت‌های باز و شناسایی سرویس روی یک هدف، با استفاده از nmap.
    """

    def __init__(self, top_ports: int = 100, timeout_seconds: int = 120):
        if shutil.which("nmap") is None:
            raise NmapNotFoundError(
                "nmap روی سیستم نصب نیست. با 'apt install nmap' نصبش کن."
            )
        self.top_ports = top_ports
        self.timeout_seconds = timeout_seconds

    def scan(self, target: str) -> list[OpenPort]:
        """هدف رو اسکن می‌کنه و لیست پورت‌های باز با سرویس شناسایی‌شده رو برمی‌گردونه."""
        cmd = [
            "nmap",
            "-sV",                 # شناسایی نسخه سرویس
            "--top-ports", str(self.top_ports),
            "-T4",                 # سرعت متعادل
            "-oX", "-",             # خروجی XML روی stdout
            target,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError(f"اجرای nmap شکست خورد: {result.stderr.strip()}")

        return self._parse_xml(result.stdout)

    @staticmethod
    def _parse_xml(xml_text: str) -> list[OpenPort]:
        open_ports: list[OpenPort] = []
        root = ET.fromstring(xml_text)

        for host in root.findall("host"):
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""

                open_ports.append(
                    OpenPort(
                        port=int(port_el.get("portid")),
                        protocol=port_el.get("protocol", "tcp"),
                        service=service_name,
                        product=product,
                        version=version,
                    )
                )
        return open_ports